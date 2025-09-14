#!/bin/bash
# encrypt_wrapper.sh
# Usage:
#   Encrypt file:   ./encrypt_wrapper.sh encrypt file <input_file> <output_file> "<key_string>" [derive|pad]
#   Decrypt file:   ./encrypt_wrapper.sh decrypt file <input_file> <output_file> "<key_string>"
#   Encrypt string: ./encrypt_wrapper.sh encrypt string "<text_to_encrypt>" "<key_string>" [derive|pad]
#   Decrypt string: ./encrypt_wrapper.sh decrypt string "<base64_text>" "<key_string>"

ACTION="$1"  # encrypt or decrypt
TYPE="$2"    # file or string

if [ "$ACTION" == "encrypt" ]; then
    if [ "$TYPE" == "file" ]; then
        INPUT_FILE="$3"
        OUTPUT_FILE="$4"
        KEY_STRING="$5"
        MODE="${6:-derive}"

        if [ ! -f "$INPUT_FILE" ]; then
            echo "[ERROR] Input file '$INPUT_FILE' does not exist."
            exit 1
        fi

        python3 chacha_encrypt.py encrypt "$INPUT_FILE" "$OUTPUT_FILE" --key "$KEY_STRING" --mode "$MODE"
        EXIT_CODE=$?

        if [ $EXIT_CODE -eq 0 ]; then
            echo "[+] Encryption successful, removing original file: $INPUT_FILE"
            rm "$INPUT_FILE"
            echo "[+] Original file removed."
        else
            echo "[ERROR] Encryption failed. Original file was not removed."
            exit $EXIT_CODE
        fi

    elif [ "$TYPE" == "string" ]; then
        TEXT="$3"
        KEY_STRING="$4"
        MODE="${5:-derive}"

        RESULT=$(python3 chacha_encrypt.py encrypt-string "$TEXT" --key "$KEY_STRING" --mode "$MODE")
        EXIT_CODE=$?

        if [ $EXIT_CODE -eq 0 ]; then
            echo "[+] Encrypted string (base64):"
            echo "$RESULT"
        else
            echo "[ERROR] String encryption failed."
            exit $EXIT_CODE
        fi
    else
        echo "[ERROR] Unknown type: $TYPE"
        exit 1
    fi

elif [ "$ACTION" == "decrypt" ]; then
    if [ "$TYPE" == "file" ]; then
        INPUT_FILE="$3"
        OUTPUT_FILE="$4"
        KEY_STRING="$5"

        if [ ! -f "$INPUT_FILE" ]; then
            echo "[ERROR] Input file '$INPUT_FILE' does not exist."
            exit 1
        fi

        python3 chacha_encrypt.py decrypt "$INPUT_FILE" "$OUTPUT_FILE" --key "$KEY_STRING"
        EXIT_CODE=$?

        if [ $EXIT_CODE -eq 0 ]; then
            echo "[+] File decrypted successfully: $OUTPUT_FILE"
            rm "$INPUT_FILE"
            echo "[+] Original file removed."
        else
            echo "[ERROR] File decryption failed."
            exit $EXIT_CODE
        fi

    elif [ "$TYPE" == "string" ]; then
        B64_TEXT="$3"
        KEY_STRING="$4"

        RESULT=$(python3 chacha_encrypt.py decrypt-string "$B64_TEXT" --key "$KEY_STRING")
        EXIT_CODE=$?

        if [ $EXIT_CODE -eq 0 ]; then
            echo "[+] Decrypted string:"
            echo "$RESULT"
        else
            echo "[ERROR] String decryption failed."
            exit $EXIT_CODE
        fi
    else
        echo "[ERROR] Unknown type: $TYPE"
        exit 1
    fi

else
    echo "Usage:"
    echo "  Encrypt file:   $0 encrypt file <input_file> <output_file> \"<key_string>\" [derive|pad]"
    echo "  Decrypt file:   $0 decrypt file <input_file> <output_file> \"<key_string>\""
    echo "  Encrypt string: $0 encrypt string \"<text_to_encrypt>\" \"<key_string>\" [derive|pad]"
    echo "  Decrypt string: $0 decrypt string \"<base64_text>\" \"<key_string>\""
    exit 1
fi

