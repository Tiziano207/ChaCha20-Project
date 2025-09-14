# Variabili di default
INPUT_FILE ?= input.txt
OUTPUT_FILE ?= output.enc
KEY ?= "MySecretPassword"
MODE ?= derive
TEXT ?= "Hello, World!"

# Cifratura di un file
encrypt-file:
        @echo "Cifrando il file $(INPUT_FILE) in $(OUTPUT_FILE) con la chiave $(KEY) e modalità $(MOD>        ./encrypt_wrapper.sh encrypt file $(INPUT_FILE) $(OUTPUT_FILE) "$(KEY)" $(MODE)

# Cifratura di una stringa
encrypt-string:
        @echo "Cifrando la stringa: $(TEXT) con la chiave $(KEY) e modalità $(MODE)..."
        ./encrypt_wrapper.sh encrypt string "$(TEXT)" "$(KEY)" $(MODE)

# Decifratura di un file
decrypt-file:
        @echo "Decifrando il file $(INPUT_FILE) in $(OUTPUT_FILE) con la chiave $(KEY) e modalità $(M>        ./encrypt_wrapper.sh decrypt file $(INPUT_FILE) $(OUTPUT_FILE) "$(KEY)" $(MODE)

# Decifratura di una stringa
decrypt-string:
        @echo "Decifrando la stringa: $(TEXT) con la chiave $(KEY) e modalità $(MODE)..."
        ./encrypt_wrapper.sh decrypt string "$(TEXT)" "$(KEY)"
