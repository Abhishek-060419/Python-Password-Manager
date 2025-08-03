import json,hashlib,os,base64
from cryptography.fernet import Fernet

#Creating and Storing Master Password

def create_Master_Password(password):
    salt=os.urandom(16)                                                                  #To create a salt to improve security
    hash = hashlib.pbkdf2_hmac('sha256',password.encode(),salt,100000)                   #Create a hash for the password mixed with salt


    data={
        'Salt': base64.b64encode(salt).decode(),                                        #To convert binary hash and salt to ASCII for json file readability
        'Hash': base64.b64encode(hash).decode()
    }

    with open("Master.json","w") as f:                                                 #Storing hash and salt in json file
        json.dump(data,f)

    print("The master password has been successfully created and stored securely.")



#Verifying the Master Password

def verify_Master_Password(input_password):
    with open("Master.json","r") as f:
        data=json.load(f)

    stored_salt = base64.b64decode(data['Salt'])                                             #Retrieving stored salt value
    stored_hash = base64.b64decode(data['Hash'])                                             #Retrieving stored hash value

    input_hash = hashlib.pbkdf2_hmac('sha256',input_password.encode(),stored_salt,100000)    #Converting user given password to hash

    if input_hash==stored_hash:
        print("Password verification successful.\n Access Granted.")                         #Comparing both hash values to check integrity 
        return True 
    else:
        print("Invalid password. \n Access Denied.")
        return False




#Creating a Fernet key

def create_Fernet_Key():
    if not os.path.exists("Fernet.key"):
        key=Fernet.generate_key()                                                               #Generate a fernet key
        with open("Fernet.key","wb") as f:
            f.write(key)                                                                        #Store the fernt key in file
    else:
        print("The file already exists.")


#Loading the fernet key

def load_Key():
    with open("Fernet.key","rb") as f:
        return f.read()



#Encrypt password using Ferent Key for storing

def encrypt_Password(password):
    key=load_Key()
    fernet=Fernet(key)
    return fernet.encrypt(password.encode()).decode()                                       #return the Encrypted password 



#Decrypt the passsword using Fernet for reading

def decrypt_Password(password):
    key=load_Key()
    fernet=Fernet(key)
    return fernet.decrypt(password.encode()).decode()                                       #return the Decrypted password


#Creating Vault for storing the service details

def initialize_Vault():
    if not os.path.exists("Vault.json"):                                                #Checking if Vault json file already exists
        with open("Vault.json","w") as f:
            json.dump({},f)
    else:
        print("Vault File already exists. Initialization skipped.")



#Adding Service details to Vault

def add_Details(service,username,password):
    try:
        with open("Vault.json","r") as f:
            vault=json.load(f)
        
        encrypted_pw=encrypt_Password(password)

        vault[service]={                                                              #Adding the parametrs to the Vault json file
            'Username': username,
            'Password': encrypted_pw
        }

        with open("Vault.json","w") as f:
            json.dump(vault,f,indent=4)
    
    except FileNotFoundError:
        print("Vault file not found. Initialize file before adding details.")



#Get details for a particular service

def get_Details(service):
    try:
        with open("Vault.json") as f:
            vault=json.load(f)
        
        if service in vault:
            credentials=vault[service]  
            encr_password=credentials['Password']
            decrypted_pw=decrypt_Password(encr_password)


            print(f"Details for service: {service}")                                   #Printing the details of parameter service name
            print(f"\n Username: {credentials['Username']}")
            print(f"\nPassword: {decrypted_pw}")

        else:
            print(f"\n No service named {service} found!")
    
    except FileNotFoundError:
        print("Vault file not found. Initialize file before accessing details.")


#Display whole file contents

def display_Vault():
    try:
        with open("Vault.json","r") as f:
            vault=json.load(f)
        i=1
        for services,credentials in vault.items():
            encr_password=credentials['Password']
            decrypted_pw=decrypt_Password(encr_password)                                 #Printing the whole file contents one by one
            print(f"{i}. Service Name: {services}\n")
            print(f"Username: {credentials['Username']}")
            print(f"Password: {decrypted_pw}")
            print()
            i+=1
            
    except FileNotFoundError:
        print("Vault file not found. Initialize file before accessing contents.")
    


####### Menu driven program function #########

def menu():
    print("Welcome to Password Manager.")
    print("\n1.Create Vault File.")
    print("\n2.Create Master File.")
    print("\n3.Create Fernet key.")
    print("\n4.Add service details")
    print("\n5.Get service details")
    print("\n6.Display all services")
    print("\n7.Exit")

    while True:
        try:
            choice = int(input("Enter your choice"))
        except ValueError:
            print("Please enter an integer value!")
            continue
        
        if choice==1:
            initialize_Vault()
    
        elif choice==2:
            mstr_pswrd=input("\nEnter masterpassword:")
            create_Master_Password(mstr_pswrd)
    
        elif choice==3:
            create_Fernet_Key()
    
        elif choice==4:
            psswrd=input("\nEnter your master password:")
            if verify_Master_Password(psswrd):
                service=input("\nEnter your service name:")
                username=input("\nEnter your username:")
                password=input("\nEnter your password:")

                add_Details(service,username,password)
        
        elif choice==5:
            psswrd=input("\nEnter your master password:")
            if verify_Master_Password(psswrd):
                servie_name=input("\nEnter the name of the service to display:")
                get_Details(servie_name)
        
        elif choice==6:
            psswrd=input("\nEnter your master password:")
            if verify_Master_Password(psswrd):
                display_Vault()
        
        elif choice==7:
            print("Exiting the menu.")
            break
        
        else:
            print("Invalid choice. Try again!")
        

if __name__ == "__main__":
    menu()

