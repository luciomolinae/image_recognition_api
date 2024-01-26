from flask import Flask, request, jsonify
from flask_restful import Api, Resource
from pymongo import MongoClient
import bcrypt
import numpy as np
import request

from keras.applications import InceptionV3
from keras.applications.inception_v3 import preprocess_input
from keras.applications import imagenet_utils
from tensorflow.keras.preprocessing.image import img_to_array
from PIL import Image
from io import BytesIO


app = Flask(__name__)
api = Api(app)

# Carga del model pre-entrenado
pretained_model = InceptionV3(weigths = "imagenet")

# Inicializamos MongoClient
client = MongoClient("mongodb://db:27017")

# Creamos una nueva db y coleccion
db = client.Image.Recognition
users = db["Users"]



def user_exists(username):
    if users.count_documents({"Username":username}) == 0:
        return False
    else:
        return True

class Register(Resource):
    def post(self):
        # Obtenemos el registro del usuario
        posted_data = request.get_json()

        # Le pedimos al usuario un nombre y contraseña
        username = posted_data["username"]
        password = posted_data["password"]

        # Verificamos si el usuario existe
        if user_exists(username):
            retJson = ({
                "status": 301,
                "message" : "Usuario no valido"
            })
            return jsonify(retJson)
        
        # Hasheamos la password
        hashed_pw = bcrypt.hashpw(password.encode('utf8'), bcrypt.gensalt())

        # Almacenamos el usuario en la base
        users.insert_one({
            "Username" : username,
            "Password": hashed_pw,
            "Tokens": 4
        })

        # Si todo sale bien, informamos con 200 ok
        retJson = ({
                "status": 200,
                "message" : "Usuario creado correctamente"
            })
        return jsonify(retJson)
    
def verify_pw(username, password):
    if not users_exists(username):
        return False
    
    hashed_pw = users.find({
        "Username": username
    })[0]["Password"]

    if bcrypt.hashpw(password.encode('utf8'), hashed_pw) == hashed_pw:
        return True

    else:
        return False 

def verify_credentials(username, password):
    if not user_exists(username):
        return generate_return_dictionary(301, "Usuario Invalido"), True
    
    correct_pw = verify_pw(username, password)

    if not correct_pw:
        return generate_return_dictionary(302, "Contraseña Invalida"), True

    return None, False

def generate_return_dictionary(status, msg):
    retJson = {
        "status": status,
        "msg": msg
    }
    return retJson
  
class Classify(Resource):
    def post(self):
        # Obtenemos la posted data
        posted_data = request.get_json()

        # Obtenemos las credenciales y la url
        username = posted_data["username"]
        password = posted_data["password"]
        url = posted_data["url"]

        # Verificamos las credenciales
        retJson, error = verify_credentials(username, password)
        if error:
            return jsonify(retJson)
        
        # Verificamos si el usuario tiene tokens
        tokens = users.find({
            "Username":username
        })[0]["Tokens"]

        if tokens <= 0:
            return jsonify(generate_return_dictionary(303, "Tokens Insuficientes"))
    
        # Clasificamos la imagen
        if not url:
            return jsonify(({"error":"URL Faltante"}), 400)
        
        # Cargamos la imagen de la url
        response = requests.get(url)
        img = Image.open(BytesIO(response.content))

        # Preprocesamos la imagen
        img = img.resize((299,299))
        img_array = img_to_array(img)
        img_array = np.expand_dims(img_array, axis=0)
        img_array = preprocess_input(img_arrayg)

        # Se hace la prediccion
        prediction = pretrained_model.predict(img_array)
        actual_prediction = imagenet_utils.decode_predictions(prediction, top=5)

        # Devolvemos los resultados de la prediccion
        retJson = {}
        for pred in actual_prediction[0]:
            retJson[pred[1]] = float(pred[2]*100)

        # Le cobramos un Token al usuario
        users.update_one({
            "Username" : username
        },{
            "$set":{
                "Tokens": tokens - 1
            }
        })

        return jsonify(retJson)

class Refill(Resource):
    def post(self):
        postedData = request.get_json()

        username = postedData["username"]
        password = postedData["admin_pw"]
        refill_amount = postedData["refill"]

        # Verificamos si el usuario existe
        if not user_exists(username):
            retJson = {
                "status" : 301,
                "msg" : "Usuario no valido"
            }
            return jsonify(retJson)
        
        correct_pw = "abc123"
        if not password == correct_pw:
            retJson = {
                "status" : 304,
                "msg" : "ADMIN PASSWORD Incorrecta"
            }
            return jsonify(retJson)
        
        # Le damos los Tokens y respondemos 200 OK
        users.update_one({
            "Username" : username
        }, {
            "$set":{
                "Tokens" : refill_amount
            }
        })

        retJson = {
            "status" : 200,
            "msg" : "Recarga de Tokens completada"
        }
        return jsonify(retJson)


api.add_resource(Register, '/register')
api.add_resource(Classify, '/classify')
api.add_resource(Refill, '/refill')

if __name__ == '__main__':
    app.run(host='0.0.0.0')