from flask import Flask, render_template, request
from RSA import run_rsa_demo
from Elgamal import run_elgamal_demo
from ECC import run_ecc_demo   # Updated as requested

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def index():
    result = None

    if request.method == "POST":
        plaintext = request.form["plaintext"]

        # Run algorithms
        rsa = run_rsa_demo(plaintext)
        elgamal = run_elgamal_demo(plaintext)
        ecc = run_ecc_demo(plaintext)

        # Store results
        result = {
            "RSA": rsa,
            "ElGamal": elgamal,
            "ECC": ecc
        }

    return render_template("index.html", result=result)


if __name__ == "__main__":
    app.run(debug=True)
