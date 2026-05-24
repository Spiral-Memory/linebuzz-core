CREATE TABLE internal.bip39_words (
  id   integer NOT NULL,
  word text    NOT NULL
);

CREATE INDEX idx_bip39_words_id ON internal.bip39_words (id);

ALTER TABLE internal.bip39_words
  ENABLE ROW LEVEL SECURITY;

ALTER TABLE internal.bip39_words
  ADD CONSTRAINT bip39_words_pkey PRIMARY KEY (id);