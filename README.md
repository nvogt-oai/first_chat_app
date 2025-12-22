# first_chat_app

Simple **TypeScript** MCP server (Calorie Tracker tools).

## Run

```bash
npm install
npm run build
npm start
```

Dev (watch mode):

```bash
npm run dev
```

The MCP endpoint is served at:

- `http://localhost:8787/mcp`

If that port is taken, run with a different port:

```bash
PORT=8790 npm start
```

## Tools

- `log_food`: `{ food, calories, date?, meal?, notes? }`
- `list_entries`: `{ date? }`
- `get_daily_summary`: `{ date? }`
- `set_daily_goal`: `{ calories }`
- `delete_entry`: `{ id }`

