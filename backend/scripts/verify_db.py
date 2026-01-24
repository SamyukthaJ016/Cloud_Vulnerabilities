"""
Database Verification Script
Checks that your vulnerability table is properly set up
"""

import os
import psycopg2
from dotenv import load_dotenv

load_dotenv()

def verify_database():
    """Verify the vulnerabilities table exists and has correct schema"""
    
    print("="*60)
    print("DATABASE VERIFICATION")
    print("="*60)
    
    try:
        # Connect to database
        conn = psycopg2.connect(os.getenv("DATABASE_URL"))
        cur = conn.cursor()
        
        print("\n✓ Connected to database")
        
        # Check if vulnerabilities table exists
        cur.execute("""
            SELECT EXISTS (
                SELECT FROM information_schema.tables 
                WHERE table_name = 'vulnerabilities'
            );
        """)
        
        table_exists = cur.fetchone()[0]
        
        if not table_exists:
            print("\n✗ FAILED: 'vulnerabilities' table does not exist!")
            print("\nRun this command to create it:")
            print("""
psql $DATABASE_URL -c "
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id SERIAL PRIMARY KEY,
    scan_id INTEGER REFERENCES scans(id),
    resource_id INTEGER REFERENCES resources(id),
    vuln_id VARCHAR(255) NOT NULL,
    title VARCHAR(500) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    description TEXT,
    affected_package VARCHAR(255),
    fixed_version VARCHAR(100),
    cvss_score DECIMAL(3,1),
    tool VARCHAR(50),
    reference_urls TEXT,
    created_at TIMESTAMP DEFAULT NOW()
);
CREATE INDEX idx_vuln_severity ON vulnerabilities(severity);
CREATE INDEX idx_vuln_scan ON vulnerabilities(scan_id);
CREATE INDEX idx_vuln_id ON vulnerabilities(vuln_id);
CREATE INDEX idx_vuln_cvss ON vulnerabilities(cvss_score DESC);
"
            """)
            return False
        
        print("✓ 'vulnerabilities' table exists")
        
        # Check table schema
        cur.execute("""
            SELECT column_name, data_type, is_nullable
            FROM information_schema.columns
            WHERE table_name = 'vulnerabilities'
            ORDER BY ordinal_position;
        """)
        
        columns = cur.fetchall()
        
        print("\n📋 Table Schema:")
        print(f"{'Column':<20} {'Type':<20} {'Nullable':<10}")
        print("-"*50)
        
        expected_columns = {
            'id', 'scan_id', 'resource_id', 'vuln_id', 'title', 
            'severity', 'description', 'affected_package', 'fixed_version',
            'cvss_score', 'tool', 'reference_urls', 'created_at'
        }
        
        found_columns = set()
        
        for col_name, col_type, nullable in columns:
            print(f"{col_name:<20} {col_type:<20} {nullable:<10}")
            found_columns.add(col_name)
        
        # Check for missing columns
        missing_columns = expected_columns - found_columns
        if missing_columns:
            print(f"\n⚠ WARNING: Missing columns: {', '.join(missing_columns)}")
        else:
            print("\n✓ All expected columns present")
        
        # Check for reference_urls specifically (common issue)
        if 'reference_urls' in found_columns:
            print("✓ Using 'reference_urls' column (correct for PostgreSQL)")
        elif 'references' in found_columns:
            print("⚠ WARNING: Using 'references' column name")
            print("  PostgreSQL reserves 'references' as a keyword")
            print("  Consider renaming to 'reference_urls'")
        
        # Check indexes
        cur.execute("""
            SELECT indexname, indexdef
            FROM pg_indexes
            WHERE tablename = 'vulnerabilities'
            ORDER BY indexname;
        """)
        
        indexes = cur.fetchall()
        
        print("\n📊 Indexes:")
        for idx_name, idx_def in indexes:
            print(f"  ✓ {idx_name}")
        
        expected_indexes = {
            'idx_vuln_severity',
            'idx_vuln_scan', 
            'idx_vuln_id',
            'idx_vuln_cvss'
        }
        
        found_indexes = {idx[0] for idx in indexes if idx[0].startswith('idx_vuln')}
        missing_indexes = expected_indexes - found_indexes
        
        if missing_indexes:
            print(f"\n⚠ WARNING: Missing indexes: {', '.join(missing_indexes)}")
        else:
            print("✓ All expected indexes present")
        
        # Check foreign key constraints
        cur.execute("""
            SELECT
                tc.constraint_name,
                tc.table_name,
                kcu.column_name,
                ccu.table_name AS foreign_table_name,
                ccu.column_name AS foreign_column_name
            FROM information_schema.table_constraints AS tc
            JOIN information_schema.key_column_usage AS kcu
              ON tc.constraint_name = kcu.constraint_name
            JOIN information_schema.constraint_column_usage AS ccu
              ON ccu.constraint_name = tc.constraint_name
            WHERE tc.constraint_type = 'FOREIGN KEY'
              AND tc.table_name = 'vulnerabilities';
        """)
        
        fks = cur.fetchall()
        
        print("\n🔗 Foreign Keys:")
        for fk in fks:
            print(f"  ✓ {fk[2]} → {fk[3]}.{fk[4]}")
        
        # Test insert and select (with rollback)
        print("\n🧪 Testing Operations...")
        
        try:
            # Start transaction
            cur.execute("BEGIN;")
            
            # Test insert
            cur.execute("""
                INSERT INTO vulnerabilities 
                (scan_id, resource_id, vuln_id, title, severity, description, 
                 affected_package, fixed_version, cvss_score, tool, reference_urls)
                VALUES (1, 1, 'CVE-TEST-001', 'Test Vulnerability', 'HIGH', 
                        'Test description', 'test-package 1.0', '1.1', 7.5, 
                        'test-tool', '["https://example.com"]')
                RETURNING id;
            """)
            
            test_id = cur.fetchone()[0]
            print(f"  ✓ INSERT test passed (id: {test_id})")
            
            # Test select
            cur.execute("""
                SELECT vuln_id, title, severity, cvss_score 
                FROM vulnerabilities 
                WHERE id = %s;
            """, (test_id,))
            
            result = cur.fetchone()
            print(f"  ✓ SELECT test passed")
            
            # Rollback test transaction
            cur.execute("ROLLBACK;")
            print("  ✓ Test transaction rolled back")
            
        except Exception as e:
            cur.execute("ROLLBACK;")
            print(f"  ✗ Operation test failed: {e}")
            return False
        
        # Get table statistics
        cur.execute("SELECT COUNT(*) FROM vulnerabilities;")
        vuln_count = cur.fetchone()[0]
        
        print(f"\n📈 Statistics:")
        print(f"  Current vulnerability records: {vuln_count}")
        
        cur.close()
        conn.close()
        
        print("\n" + "="*60)
        print("✅ DATABASE VERIFICATION PASSED")
        print("="*60)
        print("\nYour database is ready for vulnerability scanning!")
        
        return True
        
    except Exception as e:
        print(f"\n✗ ERROR: {e}")
        print("\nMake sure:")
        print("1. PostgreSQL is running")
        print("2. DATABASE_URL is set in .env")
        print("3. You have proper permissions")
        return False


if __name__ == "__main__":
    import sys
    success = verify_database()
    sys.exit(0 if success else 1)
