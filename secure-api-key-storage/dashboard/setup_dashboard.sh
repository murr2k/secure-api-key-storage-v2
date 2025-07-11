#!/bin/bash

# Dashboard Setup Script
# This script helps you set up and run the dashboard

set -e  # Exit on error

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}Secure API Key Storage Dashboard Setup${NC}"
echo -e "${GREEN}========================================${NC}"

# Check if we're in the dashboard directory
if [ ! -f "README.md" ] || [ ! -d "backend" ] || [ ! -d "frontend" ]; then
    echo -e "${RED}Error: Please run this script from the dashboard directory${NC}"
    exit 1
fi

# Backend setup
echo -e "\n${YELLOW}Setting up Backend...${NC}"
cd backend

# Check if .env exists
if [ ! -f ".env" ]; then
    echo -e "${YELLOW}Creating .env file from template...${NC}"
    cp .env.example .env
    echo -e "${RED}IMPORTANT: Edit backend/.env and set your master password!${NC}"
    echo -e "${RED}API_KEY_MASTER=your-secure-password${NC}"
    echo ""
    read -p "Press Enter after you've edited the .env file..."
fi

# Install Python dependencies
if [ ! -d "venv" ]; then
    echo -e "${YELLOW}Creating Python virtual environment...${NC}"
    python3 -m venv venv
fi

echo -e "${YELLOW}Installing Python dependencies...${NC}"
source venv/bin/activate
pip install -r requirements.txt

# Start backend
echo -e "\n${GREEN}Starting Backend...${NC}"
echo -e "${YELLOW}Backend will run at: http://localhost:8000${NC}"
echo -e "${YELLOW}API docs at: http://localhost:8000/docs${NC}"
echo ""

# Run backend in background
uvicorn main:app --reload --host 0.0.0.0 --port 8000 &
BACKEND_PID=$!
echo "Backend PID: $BACKEND_PID"

# Wait for backend to start
echo -e "${YELLOW}Waiting for backend to start...${NC}"
sleep 5

# Check if backend is running
if curl -s http://localhost:8000/api/health > /dev/null; then
    echo -e "${GREEN}✓ Backend is running!${NC}"
    curl -s http://localhost:8000/api/health | python3 -m json.tool
else
    echo -e "${RED}✗ Backend failed to start!${NC}"
    echo -e "${RED}Check the logs above for errors.${NC}"
    kill $BACKEND_PID 2>/dev/null
    exit 1
fi

# Frontend setup
cd ../frontend
echo -e "\n${YELLOW}Setting up Frontend...${NC}"

# Install dependencies
if [ ! -d "node_modules" ]; then
    echo -e "${YELLOW}Installing npm dependencies...${NC}"
    npm install
fi

echo -e "\n${GREEN}Starting Frontend...${NC}"
echo -e "${YELLOW}Frontend will run at: http://localhost:3000${NC}"
echo ""

# Run frontend
npm run dev &
FRONTEND_PID=$!
echo "Frontend PID: $FRONTEND_PID"

# Wait and show instructions
sleep 5
echo -e "\n${GREEN}========================================${NC}"
echo -e "${GREEN}Dashboard is running!${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo -e "Frontend: ${YELLOW}http://localhost:3000${NC}"
echo -e "Backend API: ${YELLOW}http://localhost:8000${NC}"
echo -e "API Docs: ${YELLOW}http://localhost:8000/docs${NC}"
echo ""
echo -e "${YELLOW}Login with the master password you set in backend/.env${NC}"
echo ""
echo -e "Press Ctrl+C to stop both servers"
echo ""

# Keep script running
trap "kill $BACKEND_PID $FRONTEND_PID 2>/dev/null; exit" INT
wait