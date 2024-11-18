# DHCP
##
    Dorim implementarea unui server DHCP care functioneaza printr-un proces de comunicare numit DORA:
        1. Discover - Clientul trimite un mesaj broadcast in care solicita o adresa IP;
        2. Offer - Serverul ii propune o adresa IP, pe langa alte setari;
        3. Request - Clientul confirma alegerea ofertei printr-un mesaj de solicitare;
        4. Acknowledge - Serverul confirma la randul sau, rezervand adresa IP pentru clientul respectiv.

    Serverul DHCP are urmatoarele roluri intr-o retea:
        1. Alocarea automata a adreselor IP;
        2. Lease-ul si managementul adreselor IP;
        3. Configurarea dinamica a setarilor de retea, precum:
            - Gateway implicit;
            - Server DNS;
            - Masca de subretea.
        4. Reinnoirea automata a Lease-urilor la un anumit interval de timp;
        5. Eliberarea IP-urilor (la solicitarea clientului).

    Serverul DHCP prezinta anumite avantaje, in comparatie cu alocarea statica a IP-urilor pentru clienti:
        1. Configurarea automata;
        2. Reducerea conflictelor IP;
        3. Utilizarea eficienta a adreselor IP;
        4. Flexibilitate si scalabilitate;

    Limitarile serverului DHCP:
        1. Dependenta de server;
        2. Riscuri de securitate;
        3. Interferenta cu alte retele;
        
    Pentru implementare vom folosi biblioteca de socketuri POSIX pemtru a realiza comunicarea în rețea prin sockeți UDP.
    Serverul DHCP va asculta pe portul 67, iar clientul va folosi portul 68.
    Mesajul DHCP va fi reprezentat de o structură de tipul:

    struct dhcp_message
    {
        unsigned char op;               // Opcode: 1 - cerere, 2 - raspuns
        unsigned char htype;            // Tip hardware (1 pentru Ethernet)
        unsigned char hlen;             // Lungime hardware (6 pentru 6 octeti pentru adresa MAC)
        unsigned char hops;             // Număr de hopuri
        unsigned int xid;               // ID tranzacție (aleator ales de client)
        unsigned short secs;            // Secunde trecute
        unsigned short flags;           // Flaguri
        unsigned int ciaddr;            // Client IP address
        unsigned int yiaddr;            // Your IP address
        unsigned int siaddr;            // Server IP address
        unsigned int giaddr;            // Gateway IP address
        unsigned char chaddr[16];       // Hardware address client
        char sname[64];                 // Nume server
        char file[128];                 // Nume fișier de boot
        unsigned char options[312];     // Opțiuni DHCP
    };
    
    Serverul va gestiona mesajele DHCP primite și va returna mesaje de tip OFFER ca raspuns la DISCOVER si ACK ca raspuns la REQUEST.
    Totodata serverul mentine o listă de lease-uri active care leaga adresa ip de adresa mac pentru o perioada de timp.
    Serverul nu va prezenta interfață grafică și va fi executat din linie de comandă.

    Configurarea serverului DCHP se va face printr-un fișier de configurare care va conține următoarele informații:

    -Definirea Gamelor de Adrese
        Exemplu: subnet 10.0.1.0 
        Definește intervalul de adrese IP din care serverul DHCP poate aloca adrese pentru clienți. Adresa dată este cea a rețelei locale, iar numărul de adrese va fi calulat pe baza măștii de subrețea.

    -Masca de Subrețea
        Exemplu: subnet-mask 255.255.255.0
        Specifică masca de subrețea pe care clienții o vor folosi pentru a identifica rețeaua locală.

    -Default Gateway
        Exemplu: gateway 10.0.1.1
        Specifică adresa IP a default gateway-ului pe care clienții o vor utiliza.

    -DNS
        Exemplu: dns 8.8.8.8
        Specifică adresa DNS care va fi oferită automat dispozitivelor din rețea.