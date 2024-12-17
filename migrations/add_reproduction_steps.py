import sqlite3
import os

def upgrade():
    """Add reproduction_steps column to scan_result table"""
    db_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'instance', 'vulnscan.db')
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    try:
        # Add the new column
        cursor.execute('ALTER TABLE scan_result ADD COLUMN reproduction_steps TEXT')
        conn.commit()
        print("Successfully added reproduction_steps column")
    except Exception as e:
        print(f"Error adding column: {str(e)}")
        conn.rollback()
    finally:
        conn.close()

def downgrade():
    """Remove reproduction_steps column from scan_result table"""
    db_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'instance', 'vulnscan.db')
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    try:
        # Remove the column
        cursor.execute('ALTER TABLE scan_result DROP COLUMN reproduction_steps')
        conn.commit()
        print("Successfully removed reproduction_steps column")
    except Exception as e:
        print(f"Error removing column: {str(e)}")
        conn.rollback()
    finally:
        conn.close()

if __name__ == '__main__':
    upgrade()
