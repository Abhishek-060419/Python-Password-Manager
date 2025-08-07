import json,hashlib,os,base64,getpass
from cryptography.fernet import Fernet

MASTER_FILE = "Master.json"
VAULT_FILE = "Vault.json"                                                               
FERNET_FILE = "Fernet.key"


#Creating and Storing Master Password

def create_Master_Password(password):
    salt=os.urandom(16)                                                                  #To create a salt to improve security
    hash = hashlib.pbkdf2_hmac('sha256',password.encode(),salt,100000)                   #Create a hash for the password mixed with salt


    data={
        'Salt': base64.b64encode(salt).decode(),                                        #To convert binary hash and salt to ASCII for json file readability
        'Hash': base64.b64encode(hash).decode()
    }

    with open(MASTER_FILE,"w") as f:                                                 #Storing hash and salt in json file
        json.dump(data,f)

    print("The master password has been successfully created and stored securely.")



#Verifying the Master Password

def verify_Master_Password(input_password):
    if not os.path.exists(MASTER_FILE):
        print("Master password not set up yet. Please create one first.")
        return False
    
    with open(MASTER_FILE,"r") as f:
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
    if not os.path.exists(FERNET_FILE):
        key=Fernet.generate_key()                                                               #Generate a fernet key
        with open(FERNET_FILE,"wb") as f:
            f.write(key)                                                                        #Store the fernet key in file
    else:
        print("The file already exists.")


#Loading the fernet key

def load_Key():
    with open(FERNET_FILE,"rb") as f:
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
    if not os.path.exists(VAULT_FILE):                                                #Checking if Vault json file already exists
        with open(VAULT_FILE,"w") as f:
            json.dump({},f)
    else:
        print("Vault File already exists. Initialization skipped.")



#Adding Service details to Vault

def add_Details(service,username,password):
    try:
        with open(VAULT_FILE,"r") as f:
            vault=json.load(f)
        
        encrypted_pw=encrypt_Password(password)

        vault[service]={                                                              #Adding the parameters to the Vault json file
            'Username': username,
            'Password': encrypted_pw
        }

        with open(VAULT_FILE,"w") as f:
            json.dump(vault,f,indent=4)
    
    except FileNotFoundError:
        print("Vault file not found. Initialize file before adding details.")



#Get details for a particular service

def get_Details(service):
    try:
        with open(VAULT_FILE) as f:
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
        with open(VAULT_FILE,"r") as f:
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

def check_and_setup():
    if not os.path.exists(MASTER_FILE):
        print("Setting up Master Password...")
        password1 = getpass.getpass("Create a master password: ")
        password2 = getpass.getpass("Confirm your master password: ")
        if password1 != password2:
            print("Passwords do not match.")
            return
        else:
            create_Master_Password(password1)

    if not os.path.exists(FERNET_FILE):
        print(" Creating Fernet key...")
        create_Fernet_Key()

    if not os.path.exists(VAULT_FILE):
        print("Initializing Vault...")
        initialize_Vault()


def menu():
    print("Welcome to Password Manager.")
    print("\n1.Add service details")
    print("\n2.Get service details")
    print("\n3.Display all services")
    print("\n4.Exit")

    while True:
        try:
            choice = int(input("Enter your choice"))
        except ValueError:
            print("Please enter an integer value!")
            continue
    
        if choice==1:
            psswrd=getpass.getpass("\nEnter your master password:")
            if verify_Master_Password(psswrd):
                service=input("\nEnter your service name:").strip()
                username=input("\nEnter your username:").strip()
                password=input("\nEnter your password:")

                add_Details(service,username,password)
                success = add_details(service, username, password)
                if success:
                    print("Details added successfully!")
                else:
                    print("Failed to add details.")
        
        elif choice==2:
            psswrd=getpass.getpass("\nEnter your master password:")
            if verify_Master_Password(psswrd):
                servie_name=input("\nEnter the name of the service to display:").strip()
                get_Details(servie_name)
        
        elif choice==3:
            psswrd=getpass.getpass("\nEnter your master password:")
            if verify_Master_Password(psswrd):
                display_Vault()
        
        elif choice==4:
            print("Exiting the menu.")
            break
        
        else:
            print("Invalid choice. Try again!")
        

if __name__ == "__main__":
    check_and_setup()
    menu()

