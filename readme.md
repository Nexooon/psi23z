<h1>Network programming project</h1>
<br>
<h2>CBOR to JSON converter using gateway</h2>
<br>
<h1>Simple run</h1>

    ```bash
    python3 gateway.py
    python3 recorder.py
    python3 sensory_device.py


<h1>using docker</h1>

    ```bash
    #podstawowa konfiguracje mozemy przetestowac uruchmiajac kolejno, brame, rejesetrator, urzadznie ze skryptow build i run
    #wygodniej to zrobic docker compose

    #za pomoca docker compose
    #1. podstawowa konfiguracja
    docker compose -f docker-compose-basic.yml build
    docker compose -f docker-compose-basic.yml up

    #2. wiecej urzadzen sensorycznych
    docker compose -f docker-compose-more-clients.yml build
    docker compose -f docker-compose-more-clients.yml up

    #3. wiecej rejestratorow
    docker compose -f docker-compose-more-recorders.yml build
    docker compose -f docker-compose-more-clients.yml up

    #itd...
    
    

 
