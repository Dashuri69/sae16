import re
import csv

IP_pattern = re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')

with open("Exam.txt","r") as f:
   
    compteur_http = 0
    compteur_https = 0
    compteur_http_final = 0
    compteur_domaine = 0
    compteur_ssh = 0  
    compteur_icmp = 0
    compteur_icmp_req = 0
    compteur_icmp_rep = 0
    compteur_flags_connexion = 0
    compteur_flags_SynAcK = 0
    compteur_flags_deco = 0
    compteur_flags_push = 0
    compteur_flags_nokonnexion = 0
    compteur = 0
    tab = [0]*60
     
    for line in f:
        match = re.search(r"\d{2}:\d{2}:\d{2}", line)
        if match:
            tab[int(line[6]+line[7])]+=1
            if 'http' in line:
                compteur_http = compteur_http +1
                compteur_http_final  = compteur_http - compteur_https
            if '.domain' in line:
                compteur_domaine = compteur_domaine + 1
            if 'ssh' in line:
                compteur_ssh = compteur_ssh +1
            if 'https' in line:
                compteur_https = compteur_https + 1
            if 'ICMP' in line:
                compteur_icmp = compteur_icmp + 1
            if 'ICMP echo request' in line:
                compteur_icmp_req = compteur_icmp_req + 1
            if 'ICMP echo reply' in line:
                compteur_icmp_rep = compteur_icmp_rep + 1
            if 'Flags [S]' in line:
                compteur_flags_connexion = compteur_flags_connexion +1
            if 'Flags [S.]' in line:
                compteur_flags_SynAcK = compteur_flags_SynAcK +1
            if 'Flags [F.]' in line:
                compteur_flags_deco = compteur_flags_deco +1
            if 'Flags [P.]' in line:
                compteur_flags_push = compteur_flags_push +1
            if 'Flags [.]' in line:
                compteur_flags_nokonnexion = compteur_flags_nokonnexion +1
            for ip in IP_pattern.findall(line):
                compteur += 1
    print("nb",compteur,"d'ip")
           
    with open('doc.csv','a') as file:
        fieldnames = ["secondes","nb de trame"]
        writer =csv.DictWriter(file, delimiter = ";", fieldnames=fieldnames)
        writer.writeheader()
        for i in range(len(tab)):
            if tab[i] > 350:
                writer.writerow({"secondes" : i, "nb de trame": tab[i]})
        file.close()
                   
   
   
    print("Le protocol et le nombre de trames associées:")
    print('ssh:',compteur_ssh)
    print("http:",compteur_http_final)
    print("https:",compteur_https)
    print("dns:",compteur_domaine)
    print("icmp total:",compteur_icmp)
    print("icmp_req:",compteur_icmp_req)
    print("icmp_rep:",compteur_icmp_rep)
    print("il ya",compteur_flags_connexion,"de connexion demandé (FLAGS)")
    print("il ya",compteur_flags_SynAcK,"packet SynAcK")
    print("il ya",compteur_flags_deco," flags de deco demandé")
    print("il ya",compteur_flags_push,"flags pushs")
    print("il ya",compteur_flags_nokonnexion,"No Flag Set")
    if compteur_icmp_rep != compteur_icmp_req:
     print("possible attack")

