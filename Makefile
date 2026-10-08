.PHONY: help install seed test run-backend run-frontend run-standalone evaluate reset docker-up docker-down

help:
	@echo "CYBERSCOPE Development Commands:"
	@echo "  make install         Install backend and frontend dependencies"
	@echo "  make seed            Seed database with demo scenario (Operation Phantom KYC)"
	@echo "  make test            Run backend automated test suite"
	@echo "  make evaluate        Run synthetic detection benchmark evaluation"
	@echo "  make run-backend     Run FastAPI backend server"
	@echo "  make run-frontend    Run Vite frontend development server"
	@echo "  make run-standalone  Run zero-dependency Python standalone server"
	@echo "  make reset           Reset demo state to initial configuration"
	@echo "  make docker-up       Start complete stack via Docker Compose"
	@echo "  make docker-down     Stop Docker Compose stack"

install:
	cd backend && python -m pip install -r requirements.txt
	cd frontend && npm install

seed:
	cd backend && python scripts/seed_demo.py

test:
	cd backend && pytest tests/ -v

evaluate:
	cd backend && python scripts/evaluate_patterns.py

reset:
	cd backend && python scripts/reset_demo.py

run-backend:
	cd backend && uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload

run-frontend:
	cd frontend && npm run dev

run-standalone:
	cd frontend && python server.py 8000

docker-up:
	docker compose up --build -d

docker-down:
	docker compose down
