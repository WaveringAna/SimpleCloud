package main

import (
	"embed"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

//go:embed templates/*
var templateFS embed.FS

type User struct {
	ID        string    `gorm:"primarykey" json:"id"`
	Email     string    `gorm:"unique" json:"email"`
	Password  string    `json:"-"`
	IsAdmin   bool      `json:"isAdmin"`
	Files     []File    `gorm:"foreignKey:UserID"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

type File struct {
	ID          string    `gorm:"primarykey" json:"id"`
	Name        string    `json:"name"`
	Size        int64     `json:"size"`
	UploadedAt  time.Time `json:"uploadedAt"`
	ContentType string    `json:"contentType"`
	UserID      string    `json:"userId"`
	User        User      `gorm:"foreignKey:UserID"`
	CreatedAt   time.Time `json:"createdAt"`
	UpdatedAt   time.Time `json:"updatedAt"`
}

type FileService struct {
	storageDir string
	db         *gorm.DB
	templates  *template.Template
	jwtKey     []byte
}

func NewFileService(storageDir string) (*FileService, error) {
	// Create storage directory if it doesn't exist
	if err := os.MkdirAll(storageDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create storage directory: %w", err)
	}

	// Initialize database
	db, err := gorm.Open(sqlite.Open("drive.db"), &gorm.Config{})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	// Auto migrate the schemas
	if err := db.AutoMigrate(&User{}, &File{}); err != nil {
		return nil, fmt.Errorf("failed to migrate database: %w", err)
	}

	var adminCount int64
	db.Model(&User{}).Where("is_admin = ?", true).Count(&adminCount)

	if adminCount == 0 {
		setupToken := uuid.New().String()
		if err := os.WriteFile("admin_setup_token.txt", []byte(setupToken), 0600); err != nil {
			return nil, fmt.Errorf("failed to create admin setup token: %w", err)
		}
		fmt.Printf("Admin setup token created: %s\n", setupToken)
	}

	funcMap := template.FuncMap{
		"formatBytes": formatBytes,
	}
	templates := template.Must(template.New("").Funcs(funcMap).ParseFS(templateFS, "templates/*.html"))

	return &FileService{
		storageDir: storageDir,
		db:         db,
		templates:  templates,
		jwtKey:     []byte("your-secret-key"), // In production, use an environment variable
	}, nil
}

func formatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

func (fs *FileService) authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("auth_token")
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		token, err := jwt.Parse(cookie.Value, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return fs.jwtKey, nil
		})

		if err != nil || !token.Valid {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		r.Header.Set("User-ID", claims["user_id"].(string))
		next.ServeHTTP(w, r)
	}
}

func (fs *FileService) RegisterHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		fs.templates.ExecuteTemplate(w, "register.html", nil)
		return
	}

	email := r.FormValue("email")
	password := r.FormValue("password")

	var existingUser User
	if result := fs.db.Where("email = ?", email).First(&existingUser); result.Error == nil {
		w.WriteHeader(http.StatusBadRequest)
		fs.templates.ExecuteTemplate(w, "register.html", "Email already exists")
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	user := User{
		ID:       uuid.New().String(),
		Email:    email,
		Password: string(hashedPassword),
	}

	if result := fs.db.Create(&user); result.Error != nil {
		http.Error(w, "Failed to create user", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (fs *FileService) LoginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		fs.templates.ExecuteTemplate(w, "login.html", nil)
		return
	}

	email := r.FormValue("email")
	password := r.FormValue("password")

	var user User
	if result := fs.db.Where("email = ?", email).First(&user); result.Error != nil {
		w.WriteHeader(http.StatusUnauthorized)
		fs.templates.ExecuteTemplate(w, "login.html", "Invalid credentials")
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		fs.templates.ExecuteTemplate(w, "login.html", "Invalid credentials")
		return
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": user.ID,
		"email":   user.Email,
		"exp":     time.Now().Add(24 * time.Hour).Unix(),
	})

	tokenString, err := token.SignedString(fs.jwtKey)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "auth_token",
		Value:    tokenString,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   86400, // 24 hours
	})

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// LogoutHandler invalidates the user's session
func (fs *FileService) LogoutHandler(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     "auth_token",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (fs *FileService) RenderHomePage(w http.ResponseWriter, r *http.Request) {
	userID := r.Header.Get("User-ID")

	var user User
	if err := fs.db.First(&user, "id = ?", userID).Error; err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	var files []File
	if err := fs.db.Where("user_id = ?", userID).Find(&files).Error; err != nil {
		http.Error(w, "Failed to fetch files", http.StatusInternalServerError)
		return
	}

	data := struct {
		Files []File
		Email string
		User  User
	}{
		Files: files,
		Email: user.Email,
		User:  user,
	}

	fs.templates.ExecuteTemplate(w, "index.html", data)
}

func (fs *FileService) RenderFileList(w http.ResponseWriter, r *http.Request) {
	userID := r.Header.Get("User-ID")

	var files []File
	if err := fs.db.Where("user_id = ?", userID).Find(&files).Error; err != nil {
		http.Error(w, "Failed to fetch files", http.StatusInternalServerError)
		return
	}

	fs.templates.ExecuteTemplate(w, "file-list.html", files)
}

func (fs *FileService) Upload(w http.ResponseWriter, r *http.Request) {
	userID := r.Header.Get("User-ID")

	if err := r.ParseMultipartForm(32 << 20); err != nil {
		http.Error(w, "Failed to parse form", http.StatusBadRequest)
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "Failed to get file from form", http.StatusBadRequest)
		return
	}
	defer file.Close()

	fileID := uuid.New().String()

	dst, err := os.Create(filepath.Join(fs.storageDir, fileID))
	if err != nil {
		http.Error(w, "Failed to create file", http.StatusInternalServerError)
		return
	}
	defer dst.Close()

	if _, err := io.Copy(dst, file); err != nil {
		http.Error(w, "Failed to save file", http.StatusInternalServerError)
		return
	}

	fileInfo := File{
		ID:          fileID,
		Name:        header.Filename,
		Size:        header.Size,
		UploadedAt:  time.Now(),
		ContentType: header.Header.Get("Content-Type"),
		UserID:      userID,
	}

	if err := fs.db.Create(&fileInfo).Error; err != nil {
		http.Error(w, "Failed to save file metadata", http.StatusInternalServerError)
		return
	}

	fs.RenderFileList(w, r)
}

func (fs *FileService) Delete(w http.ResponseWriter, r *http.Request) {
	userID := r.Header.Get("User-ID")
	vars := mux.Vars(r)
	fileID := vars["id"]

	var file File
	if err := fs.db.Where("id = ? AND user_id = ?", fileID, userID).First(&file).Error; err != nil {
		http.Error(w, "File not found", http.StatusNotFound)
		return
	}

	// Delete the physical file
	filePath := filepath.Join(fs.storageDir, fileID)
	if err := os.Remove(filePath); err != nil {
		http.Error(w, "Failed to delete file", http.StatusInternalServerError)
		return
	}

	// Delete the database record
	if err := fs.db.Delete(&file).Error; err != nil {
		http.Error(w, "Failed to delete file record", http.StatusInternalServerError)
		return
	}

	fs.RenderFileList(w, r)
}

func (fs *FileService) CheckAdminSetup(w http.ResponseWriter, r *http.Request) {
	// Skip admin check for login and register routes
	if r.URL.Path == "/login" || r.URL.Path == "/register" {
		return
	}

	var adminCount int64
	fs.db.Model(&User{}).Where("is_admin = ?", true).Count(&adminCount)

	if adminCount == 0 {
		http.Redirect(w, r, "/setup-admin", http.StatusSeeOther)
		return
	}

	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (fs *FileService) SetupAdminHandler(w http.ResponseWriter, r *http.Request) {
	var adminCount int64
	fs.db.Model(&User{}).Where("is_admin = ?", true).Count(&adminCount)

	if adminCount > 0 {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	if r.Method == "GET" {
		fs.templates.ExecuteTemplate(w, "setup-admin.html", nil)
		return
	}

	setupToken := r.FormValue("setup_token")
	storedToken, err := os.ReadFile("admin_setup_token.txt")
	if err != nil || setupToken != string(storedToken) {
		w.WriteHeader(http.StatusBadRequest)
		fs.templates.ExecuteTemplate(w, "setup-admin.html", "Invalid setup token")
		return
	}

	email := r.FormValue("email")
	password := r.FormValue("password")

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	admin := User{
		ID:       uuid.New().String(),
		Email:    email,
		Password: string(hashedPassword),
		IsAdmin:  true,
	}

	if result := fs.db.Create(&admin); result.Error != nil {
		http.Error(w, "Failed to create admin user", http.StatusInternalServerError)
		return
	}

	// Delete setup token file
	os.Remove("admin_setup_token.txt")

	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (fs *FileService) CreateUserHandler(w http.ResponseWriter, r *http.Request) {
	userID := r.Header.Get("User-ID")

	var admin User
	if err := fs.db.First(&admin, "id = ? AND is_admin = ?", userID, true).Error; err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	if r.Method == "GET" {
		fs.templates.ExecuteTemplate(w, "create-user.html", nil)
		return
	}

	email := r.FormValue("email")
	password := r.FormValue("password")

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	user := User{
		ID:       uuid.New().String(),
		Email:    email,
		Password: string(hashedPassword),
		IsAdmin:  false,
	}

	if result := fs.db.Create(&user); result.Error != nil {
		http.Error(w, "Failed to create user", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/users", http.StatusSeeOther)
}

func (fs *FileService) UsersListHandler(w http.ResponseWriter, r *http.Request) {
	userID := r.Header.Get("User-ID")

	var admin User
	if err := fs.db.First(&admin, "id = ? AND is_admin = ?", userID, true).Error; err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var users []User
	if err := fs.db.Find(&users).Error; err != nil {
		http.Error(w, "Failed to fetch users", http.StatusInternalServerError)
		return
	}

	fs.templates.ExecuteTemplate(w, "users-list.html", users)
}

// ProfileHandler manages user profile updates
// Requires authentication via authMiddleware
// GET: Displays the profile edit form
// POST: Updates user email and/or password
func (fs *FileService) ProfileHandler(w http.ResponseWriter, r *http.Request) {
	userID := r.Header.Get("User-ID")

	var user User
	if err := fs.db.First(&user, "id = ?", userID).Error; err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	if r.Method == "GET" {
		data := struct {
			User  User
			Error string
		}{
			User:  user,
			Error: "",
		}
		fs.templates.ExecuteTemplate(w, "profile.html", data)
		return
	}

	email := r.FormValue("email")
	currentPassword := r.FormValue("current_password")
	newPassword := r.FormValue("new_password")

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(currentPassword)); err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		fs.templates.ExecuteTemplate(w, "profile.html", map[string]interface{}{
			"User":  user,
			"Error": "Current password is incorrect",
		})
		return
	}

	updates := map[string]interface{}{"email": email}
	if newPassword != "" {
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
		if err != nil {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		updates["password"] = string(hashedPassword)
	}

	if err := fs.db.Model(&user).Updates(updates).Error; err != nil {
		http.Error(w, "Failed to update profile", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// main initializes and starts the file storage web service
// It sets up:
// - File storage service with local directory
// - Router with middleware for admin checks
// - Public routes (login, register, setup)
// - Protected routes requiring authentication
// - Admin-only routes
// - Static file serving
// The server listens on port 8080
func main() {
	fileService, err := NewFileService("./storage")
	if err != nil {
		log.Fatalf("Failed to initialize service: %v", err)
	}

	router := mux.NewRouter()

	// Middleware to check for admin setup and redirect if needed
	router.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip admin check for static files and certain routes
			if strings.HasPrefix(r.URL.Path, "/static/") ||
				r.URL.Path == "/login" ||
				r.URL.Path == "/register" ||
				r.URL.Path == "/setup-admin" {
				next.ServeHTTP(w, r)
				return
			}

			var adminCount int64
			fileService.db.Model(&User{}).Where("is_admin = ?", true).Count(&adminCount)

			if adminCount == 0 && r.URL.Path != "/setup-admin" {
				http.Redirect(w, r, "/setup-admin", http.StatusSeeOther)
				return
			}

			next.ServeHTTP(w, r)
		})
	})

	// Public routes
	router.HandleFunc("/setup-admin", fileService.SetupAdminHandler)
	router.HandleFunc("/login", fileService.LoginHandler)
	router.HandleFunc("/logout", fileService.LogoutHandler)

	// Protected routes
	router.HandleFunc("/", fileService.authMiddleware(fileService.RenderHomePage)).Methods("GET")
	router.HandleFunc("/files", fileService.authMiddleware(fileService.RenderFileList)).Methods("GET")
	router.HandleFunc("/upload", fileService.authMiddleware(fileService.Upload)).Methods("POST")
	router.HandleFunc("/files/{id}", fileService.authMiddleware(fileService.Delete)).Methods("DELETE")
	router.HandleFunc("/files/{id}/download", fileService.authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		userID := r.Header.Get("User-ID")
		vars := mux.Vars(r)
		fileID := vars["id"]

		var file File
		if err := fileService.db.Where("id = ? AND user_id = ?", fileID, userID).First(&file).Error; err != nil {
			http.Error(w, "File not found", http.StatusNotFound)
			return
		}

		filePath := filepath.Join(fileService.storageDir, fileID)
		f, err := os.Open(filePath)
		if err != nil {
			http.Error(w, "Failed to open file", http.StatusInternalServerError)
			return
		}
		defer f.Close()

		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", file.Name))
		w.Header().Set("Content-Type", file.ContentType)

		io.Copy(w, f)
	})).Methods("GET")
	router.HandleFunc("/profile", fileService.authMiddleware(fileService.ProfileHandler))

	// Admin routes
	router.HandleFunc("/users", fileService.authMiddleware(fileService.UsersListHandler)).Methods("GET")
	router.HandleFunc("/users/create", fileService.authMiddleware(fileService.CreateUserHandler))

	// Serve static files
	router.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	fmt.Println("Server starting on :8080...")
	log.Fatal(http.ListenAndServe(":8080", router))
}
