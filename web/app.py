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

#FUNÇÕES UTILITÁRIAS
def generate_json_response(status, msg):
    retJson = {
        "status_code": status,
        "msg": msg
    }
    return retJson

def userExist(username):
    user = users.find_one({"Username": username})
    if user:
        return True
    return False

def verifyCredentials(username, password):
    if not userExist(username):
        return generate_json_response(301, 'Username ou password inválido'), True
    
    hashed_pw = users.find_one({"Username": username})["Password"]

    if bcrypt.hashpw(password.encode('utf8'), hashed_pw) == hashed_pw:
        return generate_json_response(302, 'Username ou password inválido'), True
#FUNÇÕES UTILITÁRIAS

#Resourse para o registro de Usuários no Banco
class Register(Resource):
    def post(self):
        #Get no json da request
        postedData = request.get_json()

        #Extração das informações de usuário
        username = postedData["username"]
        password = postedData["password"]

        #Verifica se o usuário já existe ou não
        if userExist(username):
            return generate_json_response(301, 'Username ou password inválido')
        
        #Faz o HASH na senha
        hashed_pw = bcrypt.hashpw(password.encode('utf8'), bcrypt.gensalt())

        #Cadastra o usuário no BD
        users.insert_one({
            "Username": username,
            "Password": hashed_pw,
            "Balance": 0,
            "Debt_balance": 0
        })

        return generate_json_response(200, "Usuário cadastrado com sucesso.")
    
#Resource para depositar dinheiro na conta
class Add(Resource):
    def post(self):
        #Get no json da request
        postedData = request.get_json()

        #Extração das informações de usuário
        username = postedData["username"]
        password = postedData["password"]
        amount = postedData["amount"]

        #Verifica se o usuário/senha é válido ou não
        if not userExist(username):
            return generate_json_response(301, 'Username ou password inválido')
        
        hashed_pw = users.find_one({"Username": username})["Password"]
        if not bcrypt.hashpw(password.encode('utf8'), hashed_pw) == hashed_pw:
            return generate_json_response(302, 'Username ou password inválido')
        
        #Faz o depósito na conta
        balance = users.find_one({"Username": username})["Balance"]
        users.update_one({"Username": username}, {"$set": {"Balance": balance + amount}})

        return generate_json_response(200, 'Depósito feito com sucesso.')

#Resource para tranferência
class Transfer(Resource):
    def post(self):
        #Get no json da request
        postedData = request.get_json()

        #Extração das informações de usuário
        username = postedData["username"]
        password = postedData["password"]
        to_account = postedData["to_account"]
        amount = postedData["amount"]

        #Verifica se o usuário/senha é válido ou não
        if not userExist(username):
            return generate_json_response(301, 'Username ou password inválido')
        
        hashed_pw = users.find_one({"Username": username})["Password"]
        if not bcrypt.hashpw(password.encode('utf8'), hashed_pw) == hashed_pw:
            return generate_json_response(302, 'Username ou password inválido')
        
        #Verifica se a conta para quem quer tranferir é válida ou não
        if not userExist(to_account):
            return generate_json_response(303, 'Conta para quem você quer tranferir não existe')
        
        #Faz a trasnferência para a conta
        balance_from = users.find_one({"Username": username})["Balance"]
        balance_to = users.find_one({"Username": to_account})["Balance"]

        if balance_from < amount:
            return generate_json_response(304, "Saldo insuficiente.")

        users.update_one({"Username": username}, {"$set": {"Balance": balance_from-amount}})
        users.update_one({"Username": to_account}, {"$set": {"Balance": balance_to+amount}})

        return generate_json_response(200, "Transferência feita com sucesso!")

class CheckBalance(Resource):
    def get(self):
        #Get no json da request
        postedData = request.get_json()

        #Extração das informações de usuário
        username = postedData["username"]
        password = postedData["password"]

        #Verifica se o usuário/senha é válido ou não
        if not userExist(username):
            return generate_json_response(301, 'Username ou password inválido')
        
        hashed_pw = users.find_one({"Username": username})["Password"]
        if not bcrypt.hashpw(password.encode('utf8'), hashed_pw) == hashed_pw:
            return generate_json_response(302, 'Username ou password inválido')

        #Dá o get no balance
        balance = users.find_one({"Username": username})["Balance"]
        return generate_json_response(200, balance)
    
class TakeLoan(Resource):
    def post(self):
        #Get no json da request
        postedData = request.get_json()

        #Extração das informações de usuário
        username = postedData["username"]
        password = postedData["password"]
        amount = postedData["amount"]

        #Verifica se o usuário/senha é válido ou não
        if not userExist(username):
            return generate_json_response(301, 'Username ou password inválido')
        
        hashed_pw = users.find_one({"Username": username})["Password"]
        if not bcrypt.hashpw(password.encode('utf8'), hashed_pw) == hashed_pw:
            return generate_json_response(302, 'Username ou password inválido')

        #Fazer adição do valor de empréstimo na conta do usuário
        balance = users.find_one({"Username": username})["Balance"]
        users.update_one({"Username": username}, {"$set": {"Balance": balance + amount}})

        debt_balance = users.find_one({"Username": username})["Debt_balance"]
        users.update_one({"Username": username}, {"$set": {"Debt_balance": debt_balance + amount}})

        return generate_json_response(200, 'Empréstimo feito com sucesso!')
    
class PayLoan(Resource):
    def post(self):
        #Get no json da request
        postedData = request.get_json()

        #Extração das informações de usuário
        username = postedData["username"]
        password = postedData["password"]
        amount = postedData["amount"]

        #Verifica se o usuário/senha é válido ou não
        if not userExist(username):
            return generate_json_response(301, 'Username ou password inválido')
        
        hashed_pw = users.find_one({"Username": username})["Password"]
        if not bcrypt.hashpw(password.encode('utf8'), hashed_pw) == hashed_pw:
            return generate_json_response(302, 'Username ou password inválido')

        #Fazer adição do valor de empréstimo na conta do usuário
        balance = users.find_one({"Username": username})["Balance"]

        #Validando se existe esse saldo na conta do usuário
        if balance < amount:
            return generate_json_response(303, 'Saldo insuficiente.')

        #Quitação do empréstimo
        users.update_one({"Username": username}, {"$set": {"Balance": balance - amount}})
        debt_balance = users.find_one({"Username": username})["Debt_balance"]
        users.update_one({"Username": username}, {"$set": {"Debt_balance": debt_balance - amount}})

        return generate_json_response(200, 'Empréstimo quitado com sucesso.')

api.add_resource(Register, '/register')
api.add_resource(Add, '/add')
api.add_resource(Transfer, '/transfer')
api.add_resource(CheckBalance, '/balance')
api.add_resource(TakeLoan, '/takeloan')
api.add_resource(PayLoan, '/payloan')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
