# Web-Client

# Register
    In main se face citirea de la stdin a datelor necesare pentru crearea unui nou cont(username si parola).
    Se verifica pe baza cookie-ului daca utilizatorul este deja logat. Daca utilizatorul este deja logat 
    intr-un cont atunci nu i se permite sa creeze un cont nou pana cand da logout de pe contul curent.
    In urma trimiterii cererii de tip post catre server, acesta ne va da un raspuns.
    Din raspuns putem verifica daca operatia s-a putut executa cu succes.
    In cazul in care nu s-a putut executa afisam un mesaj de eroare.
    
# 2. Login:
    Citirea datelor pentru credentials se face in main, inaine de apelarea functiei de login.
    Analog cu operatia de register, se verifica pe baza cokie-ului daca 
    utilizatorul este deja logat intr-un cont.
    Se verifica pe baza raspunsului primit de la server daca operatia s-a putut executa cu succes.
    
# 3. Enter_library:
    Se verifica pe baza token-ului daca utilizatorul are deja acces la bilioteca. 
    In acest caz nu se mai trimite o cerere de acces catre server. In cazul in care utilizatorul nu are
    inca acces la biblioteca se asteapta raspunsul de la server primit pe baza cererii facute, 
    care va contine un token de acces. In cazul in care operatia s-a putut realiza cu succes,
    se extrage token-ul de acces din raspunsul de la server si se retine intr-o variabila numita
    jwt_token.
# 4. Get_books:
    Se verifica daca utilizatorul are acces la biblioteca.
    Informatiile despre cartile de care dispune utilizatorul sunt incluse in raspunsul
    de la server, in cazul in care cererea a putut fi executata cu succes. Se extrag informatiile
    din raspuns si in cazul in care utilizatorul nu dispune de nicio carte se afiseaa o lista goala
    si un mesaj care atentioneaza acest lucru.

# 5. Get_book:
    Analog cu get_books, insa de data aceasta se include id-ul cartii pentru care dorim sa afisam
    informatii in calea de acces catre server. In cazul in care cartea cu id-ul specificat nu
    exista in biblioteca utilizatorului server-ul va trimite un mesaj de eroare, semnaland acest lucru.
    In cazul in care id-ul specificat corespunde uneia dintre cartile utilizatorului se extrag
    informatiile despre carte, din raspunsul primit de la server si se afiseaza.
    
# 6. Add_book:
    Se verifica daca utilizatorul este logat si daca are acces la biblioteca.
    Se trimit datele introduse de la tastatura despre titlu, autor, gen, editura si
    numarul de pagini pe care il contine cartea, ce trebuie adaugata.
    Dupa ce se trimite cererea catre server se verifica daca operatia s-a putut realiza.
    
# 7. Delete_book:
    Se verifica daca utilizatorul este logat si daca are acces la biblioteca.
    Se introduce id-ul cartii pe care utilizatorul vrea sa o elimine in calea de
    acces catre server.
    Se trimite o cerere de tip delete catre server si se verifica din raspunsul primit
    daca operatia s-a putut realiza.

# 8. Logout:
    Se verifica daca utilizatorul este logat. In cazul in care nu este atunci se va afisa
    un mesaj care va semnala faptul ca logarea este necesara pentru efectuarea acestei comenzi.
    In cazul in care operatia se poate realiza se elimina informatia din cookie si din token.
