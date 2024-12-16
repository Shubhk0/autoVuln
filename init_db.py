from app import app, db
from models import User

def init_db():
    with app.app_context():
        # Create all tables
        db.create_all()
        
        # Create admin user if it doesn't exist
        admin_user = User.query.filter_by(username='admin').first()
        if not admin_user:
            admin = User(
                username='admin',
                email='admin@example.com',
                is_admin=True
            )
            admin.set_password('admin123')  # Change this to a secure password
            db.session.add(admin)
            db.session.commit()
            print("Admin user created successfully")
        
        print("Database initialized successfully")

if __name__ == '__main__':
    init_db() 