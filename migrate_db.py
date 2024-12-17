from app import create_app
from models import db
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def migrate_database():
    """Migrate the database schema to use end_time instead of completed_at"""
    app = create_app()
    
    with app.app_context():
        try:
            # Drop and recreate all tables
            logger.info("Dropping all tables...")
            db.drop_all()
            
            logger.info("Creating tables with new schema...")
            db.create_all()
            
            logger.info("Database migration completed successfully!")
            
        except Exception as e:
            logger.error(f"Error during migration: {str(e)}")
            raise

if __name__ == '__main__':
    migrate_database()
