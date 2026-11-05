ALTER TABLE companies ADD COLUMN automation_started_at INTEGER;
ALTER TABLE mailbox_accounts ADD COLUMN send_allowed INTEGER NOT NULL DEFAULT 0;
ALTER TABLE messages ADD COLUMN rfc_message_id TEXT;
ALTER TABLE messages ADD COLUMN thread_id TEXT;
ALTER TABLE messages ADD COLUMN is_automated INTEGER NOT NULL DEFAULT 0;
CREATE TABLE IF NOT EXISTS automation_daily(company_id TEXT NOT NULL REFERENCES companies(id),day TEXT NOT NULL,count INTEGER NOT NULL DEFAULT 0,PRIMARY KEY(company_id,day));
CREATE TABLE IF NOT EXISTS worker_health(id INTEGER PRIMARY KEY CHECK(id=1),last_tick INTEGER,last_error TEXT);
ALTER TABLE messages ADD COLUMN processing_started_at INTEGER;
