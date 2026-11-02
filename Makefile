
.PHONY: up down build bob alice logs stats status build2 logs2 a2

# Start server and Mallory in background
up:
	docker compose up -d --build as3_server attack-0 attack-1

a2: build2
	docker compose up as3_server attack-2

# Stop everything and reset saved sessions
down:
	docker compose down -v --remove-orphans

# Build Mallory
build:
	docker compose build attack-0

# Start Bob
bob:
	docker compose run --rm --name as3_bob bob

# Start Alice
alice:
	docker compose run --rm --name as3_alice alice

# View Mallory logs
logs:
	docker compose logs -f attack-0

# Monitor Bob
stats:
	docker stats as3_bob

# Show container status
status:
	docker compose ps -a

capture:
	-docker compose exec -T attack-0 tcpdump -i any -s 0 -U \
		-w /captures/attack0.pcap 'tcp port 9000 or tcp port 9001'

attack1:
	docker compose run --rm --build attack-1

# Build Attack 2
build2:
	docker compose build attack-2

# View Attack 2 logs
logs2:
	docker compose logs -f attack-2