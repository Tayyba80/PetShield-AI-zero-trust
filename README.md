# 🐶🐱 CatDog Classification with Zero Trust Architecture 🔐

A secure web application built using Flask that classifies uploaded images as **cat** or **dog** using a pre-trained deep learning model. The project follows the **Zero Trust Security Architecture**, ensuring that every step of the interaction (registration, login, file upload) is validated and authenticated with features like OTP verification, role-based access, and secure session handling.

---

## 🚀 Features

- 🔒 **User Registration & Secure Login**
- 🔑 **Email-based OTP Verification**
- 🧠 **Deep Learning Model (CNN) for Cat/Dog Prediction**
- 🖼️ **Image Upload & Classification**
- 📁 **Image Logs Stored in Database (Not Filesystem)**
- 👮 **Role-Based Access (Admin/User)**
- 🧾 **Admin Panel to View Upload Logs & User Info**
- ✅ **Security Headers & Input Validation**
- 🧪 **Model Inference on Uploaded Images in Real-Time**

---

## 🧱 Tech Stack

- **Backend**: Python, Flask
- **Frontend**: HTML, Jinja2 Templates, Bootstrap
- **Model**: TensorFlow/Keras `.h5` model
- **Database**: SQLite (with SQLAlchemy ORM)
- **Email**: Gmail SMTP for OTP
- **Security**: Zero Trust principles implemented

---

## 📂 Folder Structure

```

catDog/
│
├── static/uploads/           # (optional) temp folder if needed
├── templates/                # HTML Templates
│   ├── login.html
│   ├── register.html
│   ├── verify\_otp.html
│   ├── upload.html
│   ├── result.html
│   └── view\_upload\_logs.html
│
├── models/
│   └── user\_model.py         # SQLAlchemy models for User & Upload Logs
│
├── model/                    # ML Model folder
│   └── dogcat\_model\_bak.h5   # Pre-trained Keras Model
│
├── .env                      # Stores SMTP credentials
├── app.py                    # Main Flask Application
├── requirements.txt          # Project Dependencies
└── README.md                 # You're here!

````

---

## 🔐 Zero Trust Security Highlights

- **No trust by default**: Every user must verify identity via OTP.
- **Session-based access control** with `session['authenticated']`.
- **Role-based functionality** for Admin vs. User.
- **Security headers** added in responses.
- **Database access only through ORM** with hashed passwords.

---

## 🧪 How to Run Locally

### 1. Clone the Repo

```bash
git clone https://github.com/your-username/catdog-zero-trust.git
cd catdog-zero-trust
````

### 2. Create a Virtual Environment

```bash
python -m venv myenv
source myenv/bin/activate  # For Linux/macOS
myenv\Scripts\activate     # For Windows
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Set Up Environment Variables

Create a `.env` file:

```env
SMTP_EMAIL=your_email@gmail.com
SMTP_PASSWORD=your_email_password_or_app_password
```

### 5. Initialize the Database

In Python shell or a separate script:

```python
from app import db
db.create_all()
```

### 6. Run the App

```bash
python app.py
```

---

## 👩‍💼 Admin Access

You can hardcode an admin user in the database:

```python
from models.user_model import User
from app import db, hash_password

admin = User(name='Admin', email='admin@example.com', password=hash_password('admin123'), role='admin')
db.session.add(admin)
db.session.commit()
```

---

## 📚 Future Improvements

* ✅ Add image preview before upload
* ☁️ Store images in cloud (S3/GCS)
* 📊 Dashboard analytics for admin
* 🧠 Allow admin to retrain model with user-submitted data
* 🔒 Enforce HTTPS and JWT-based auth in production

---

## 🙏 Acknowledgments

* TensorFlow/Keras for model training
* Flask for web development
* Gmail SMTP for OTP service

---

## 📃 License

This project is licensed under the MIT License.

```
