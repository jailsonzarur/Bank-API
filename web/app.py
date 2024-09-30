from flask import Flask, request
from flask_restful import Api, Resource
from pymongo import MongoClient
import bcrypt

app = Flask(__name__)
api = Api(app)

#Instância do Banco NoSQL e da respectiva coleção
client = MongoClient("mongodb://db:27017")
db = client.BankDatabase
users = db["Users"]


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
