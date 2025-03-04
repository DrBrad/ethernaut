use core::ptr;
use core::ffi::c_void;
use core::ffi::CStr;
use std::collections::HashMap;
use std::ffi::CString;

pub struct Database {
    db: *mut c_void
}

impl Database {

    pub fn open(name: &str) -> Option<Self> {
        let c_db_name = CString::new(name).unwrap();
        let mut db: *mut c_void = ptr::null_mut();
        let rc = unsafe { sqlite3_open(c_db_name.as_ptr(), &mut db) };
        if rc != 0 {
            return None;
        }

        Some(Self {
            db
        })
    }

    pub fn create_table(&mut self, name: &str, columns: &HashMap<String, String>) {
        let mut column_definitions: Vec<String> = Vec::new();

        for (column_name, column_type) in columns {
            column_definitions.push(format!("{} {}", column_name, column_type));
        }

        let create_table = format!("CREATE TABLE IF NOT EXISTS {} (
            {}
        );", name, column_definitions.join(", "));

        execute_sql(self.db, &create_table);
    }

    pub fn insert(&mut self, table: &str, fields: &HashMap<&str, String>) {
        let field_names: Vec<&str> = fields.keys().cloned().collect();
        let field_values: Vec<String> = fields.values().cloned().collect();

        let sql = format!(
            "INSERT INTO {} ({}) VALUES ({});",
            table,
            field_names.join(", "),
            field_values.join(", ")
        );

        execute_sql(self.db, &sql);
    }

    pub fn get(&self, table: &str, fields: Option<Vec<&str>>, condition: Option<&str>) -> Vec<HashMap<String, String>> {
        let field_names = match fields {
            Some(f) => f.join(", "),
            None => "*".to_string()
        };

        let sql = match condition {
            Some(cond) => format!("SELECT {} FROM {} WHERE {}; ", field_names, table, cond),
            None => format!("SELECT {} FROM {}; ", field_names, table),
        };

        let mut documents = Vec::new();
        let query_cstr = CString::new(CString::new(sql).unwrap()).unwrap();

        unsafe {
            sqlite3_exec(
                self.db,
                query_cstr.as_ptr(),
                Some(query_callback),
                &mut documents as *mut Vec<HashMap<String, String>> as *mut c_void, // Pass the reference to the callback
                ptr::null_mut(),
            );
        }

        documents
    }

    pub fn close(&self) {
        unsafe { sqlite3_close(self.db) };
    }
}

fn execute_sql(db: *mut c_void, sql: &str) {
    let c_sql = CString::new(sql).unwrap();
    unsafe { sqlite3_exec(db, c_sql.as_ptr(), None, ptr::null_mut(), ptr::null_mut()) };
}

#[link(name = "sqlite3")]
extern "C" {
    fn sqlite3_open(filename: *const i8, db: *mut *mut c_void) -> i32;

    fn sqlite3_exec(
        db: *mut c_void,
        sql: *const i8,
        callback: Option<extern "C" fn(*mut c_void, i32, *mut *mut i8, *mut *mut i8) -> i32>,
        arg: *mut c_void,
        errmsg: *mut *mut i8
    ) -> i32;

    fn sqlite3_close(db: *mut c_void) -> i32;
}

extern "C" fn query_callback(_arg: *mut c_void, column_count: i32, column_values: *mut *mut i8, column_names: *mut *mut i8) -> i32 {
    let documents: &mut Vec<HashMap<String, String>> = unsafe {
        &mut *( _arg as *mut Vec<HashMap<String, String>> )
    };

    let mut document = HashMap::new();

    for i in 0..column_count {
        let column_name = unsafe { CStr::from_ptr(*column_names.offset(i as isize)) };
        let value = unsafe { CStr::from_ptr(*column_values.offset(i as isize)) };

        document.insert(column_name.to_string_lossy().into_owned(), value.to_string_lossy().into_owned());
    }

    documents.push(document);

    0
}
