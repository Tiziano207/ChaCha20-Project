from flask import Flask, request, send_file, render_template_string
import subprocess
import os
import tempfile

app = Flask(__name__)

HTML = """
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>ChaCha20 Encrypt/Decrypt</title>
  <style>
    body { font-family: Arial, sans-serif; text-align: center; margin-top: 50px; }
    #dropzone {
      width: 80%; height: 200px; border: 3px dashed #666; margin: auto;
      display: flex; align-items: center; justify-content: center;
      color: #666; border-radius: 12px;
    }
    #dropzone.dragover { border-color: #009688; color: #009688; }
    #filename {
      margin-top: 15px;
      font-weight: bold;
      color: #333;
    }
    form {
      margin-top: 20px;
    }
    input, select, button {
      margin: 5px;
      padding: 8px;
      font-size: 14px;
    }
  </style>
</head>
<body>
  <h1>ChaCha20 Encrypt/Decrypt</h1>
  <div id="dropzone">Drop file here</div>
  <p id="filename">No file uploaded yet</p>

  <form id="uploadForm" method="POST" enctype="multipart/form-data" action="/upload">
    <input type="file" name="file" id="fileInput" style="display:none;" />
    <input type="text" name="key" placeholder="Enter key" required />
    <select name="mode">
      <option value="derive">derive (recommended)</option>
      <option value="pad">pad (insecure)</option>
    </select>
    <select name="action">
      <option value="encrypt">Encrypt</option>
      <option value="decrypt">Decrypt</option>
    </select>
    <button type="submit">Start</button>
  </form>
  <script>
    const dropzone = document.getElementById('dropzone');
    const fileInput = document.getElementById('fileInput');
    const filenameDisplay = document.getElementById('filename');

    dropzone.addEventListener('dragover', (e) => {
      e.preventDefault();
      dropzone.classList.add('dragover');
    });

    dropzone.addEventListener('dragleave', () => {
      dropzone.classList.remove('dragover');
    });

    dropzone.addEventListener('drop', (e) => {
      e.preventDefault();
      dropzone.classList.remove('dragover');
      fileInput.files = e.dataTransfer.files;
      if (fileInput.files.length > 0) {
        filenameDisplay.textContent = "File loaded: " + fileInput.files[0].name;
      }
    });
  </script>
</body>
</html>
"""

@app.route("/")
def index():
    return render_template_string(HTML)

@app.route("/upload", methods=["POST"])
def upload():
    uploaded_file = request.files["file"]
    key = request.form["key"]
    mode = request.form.get("mode", "derive")
    action = request.form["action"]

    with tempfile.TemporaryDirectory() as tmpdir:
        in_path = os.path.join(tmpdir, uploaded_file.filename)
        #out_path = os.path.join(tmpdir, uploaded_file.filename + ".out")

        uploaded_file.save(in_path)

        # Mantieni sempre .enc come output
        out_filename = uploaded_file.filename
        if action == "encrypt":
            name, ext = os.path.splitext(uploaded_file.filename)
            out_filename = name + ".enc"
        elif action == "decrypt":
            # Se il file non termina con .enc, errore
            if not uploaded_file.filename.endswith(".enc"):
                return "Error: not an encrypted .enc file", 400
            # Mantieni nome originale + .enc
            out_filename = uploaded_file.filename[:-4]  # rimuove ".enc"
        else:
           return "Error: invalid action", 400

        out_path = os.path.join(tmpdir, out_filename)

        # Call your Python script (make sure chacha_encrypt.py is executable)
        if action == "encrypt":
            subprocess.check_call(["python3", "ChaCha/chacha_encrypt.py", "encrypt", in_path, out_path, "--key", key, "--mode", mode])
        else:
            subprocess.check_call(["python3", "ChaCha/chacha_encrypt.py", "decrypt", in_path, out_path, "--key", key])

        return send_file(out_path, as_attachment=True, download_name=os.path.basename(out_path))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=True)

