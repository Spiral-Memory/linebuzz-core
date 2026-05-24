CREATE TABLE internal.app_settings (
  key   text NOT NULL,
  value text NOT NULL
);

ALTER TABLE internal.app_settings
  ADD CONSTRAINT app_settings_pkey PRIMARY KEY (key);