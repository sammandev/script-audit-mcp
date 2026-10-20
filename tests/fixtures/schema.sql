CREATE TABLE functions (
    id INTEGER PRIMARY KEY,
    source TEXT NOT NULL,
    interface TEXT NOT NULL,
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    convention INTEGER,
    category TEXT NOT NULL DEFAULT '',
    execution_role TEXT NOT NULL DEFAULT '',
    execution_phase TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT 'fixture',
    updated_at TEXT NOT NULL DEFAULT 'fixture',
    UNIQUE (source, interface, name)
);
CREATE TABLE parameter_definitions (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    device_name TEXT NOT NULL DEFAULT '',
    description TEXT NOT NULL DEFAULT '',
    type TEXT NOT NULL DEFAULT 'string',
    unit TEXT NOT NULL DEFAULT '',
    default_value TEXT,
    allowed_values TEXT NOT NULL DEFAULT '',
    cardinality TEXT NOT NULL DEFAULT 'SINGLE',
    value_pattern TEXT NOT NULL DEFAULT '',
    required INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT 'fixture',
    updated_at TEXT NOT NULL DEFAULT 'fixture',
    UNIQUE (name, device_name)
);
CREATE TABLE criteria_definitions (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    device_name TEXT NOT NULL DEFAULT '',
    description TEXT NOT NULL DEFAULT '',
    type TEXT NOT NULL DEFAULT 'string',
    unit TEXT NOT NULL DEFAULT '',
    default_value TEXT,
    allowed_values TEXT NOT NULL DEFAULT '',
    cardinality TEXT NOT NULL DEFAULT 'SINGLE',
    value_pattern TEXT NOT NULL DEFAULT '',
    required INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT 'fixture',
    updated_at TEXT NOT NULL DEFAULT 'fixture',
    UNIQUE (name, device_name)
);
CREATE TABLE parameter_links (
    id INTEGER PRIMARY KEY,
    function_source TEXT NOT NULL,
    function_name TEXT NOT NULL,
    device_name TEXT NOT NULL DEFAULT '',
    name TEXT NOT NULL,
    position INTEGER,
    required INTEGER NOT NULL DEFAULT 0,
    source_file TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT 'fixture',
    updated_at TEXT NOT NULL DEFAULT 'fixture',
    UNIQUE (function_source, function_name, device_name, name)
);
CREATE TABLE criteria_links (
    id INTEGER PRIMARY KEY,
    function_source TEXT NOT NULL,
    function_name TEXT NOT NULL,
    device_name TEXT NOT NULL DEFAULT '',
    name TEXT NOT NULL,
    position INTEGER,
    required INTEGER NOT NULL DEFAULT 0,
    source_file TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT 'fixture',
    updated_at TEXT NOT NULL DEFAULT 'fixture',
    UNIQUE (function_source, function_name, device_name, name)
);
CREATE TABLE examples (
    id INTEGER PRIMARY KEY,
    function_source TEXT NOT NULL,
    function_name TEXT NOT NULL,
    device_name TEXT NOT NULL DEFAULT '',
    script TEXT NOT NULL,
    meaning TEXT NOT NULL DEFAULT '',
    source_file TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT 'fixture',
    updated_at TEXT NOT NULL DEFAULT 'fixture',
    UNIQUE (function_source, function_name, device_name, script)
);
