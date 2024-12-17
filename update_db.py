from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from models import db, User, Scan, ScanResult
import os

def create_app():
    app = Flask(__name__)
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///vulnscan.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    db.init_app(app)
    return app

def update_database():
    app = create_app()
    
    with app.app_context():
        # Backup existing database
        if os.path.exists('vulnscan.db'):
            print("Backing up existing database...")
            import shutil
            shutil.copy2('vulnscan.db', 'vulnscan.db.backup')
        
        print("Dropping all tables...")
        db.drop_all()
        
        print("Creating new tables with updated schema...")
        db.create_all()
        
        # Create default admin user
        admin = User.query.filter_by(username='admin').first()
        if not admin:
            admin = User(
                username='admin',
                email='admin@example.com',
                is_admin=True
            )
            admin.set_password('admin')  # Change this in production!
            db.session.add(admin)
            db.session.commit()
            print("Created admin user")
        
        print("Database update completed successfully!")

if __name__ == '__main__':
    update_database()
