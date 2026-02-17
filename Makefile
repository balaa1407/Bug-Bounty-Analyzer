.PHONY: up down build logs ps restart clean

up:
	docker compose up -d --build

build:
	docker compose build

down:
	docker compose down

logs:
	docker compose logs -f --tail=100

ps:
	docker compose ps

restart: down up

clean:
	docker compose down -v --remove-orphans
