import { createServer } from "node:http";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { z } from "zod";

type CalorieEntry = {
  id: string;
  food: string;
  calories: number;
  date: string; // YYYY-MM-DD (local)
  meal?: "breakfast" | "lunch" | "dinner" | "snack";
  notes?: string;
  createdAt: string; // ISO timestamp
};

type ToolTextContent = { type: "text"; text: string };
type DailySummary = {
  date: string;
  totalCalories: number;
  entriesCount: number;
  goalCalories?: number;
  remainingCalories?: number;
};

type CalorieToolResponse = {
  content: ToolTextContent[];
  structuredContent: {
    entries: CalorieEntry[];
    summary?: DailySummary;
  };
};

const yyyyMmDdRegex = /^\d{4}-\d{2}-\d{2}$/;

const dateInputSchema = z
  .string()
  .regex(yyyyMmDdRegex, "Expected date in YYYY-MM-DD format");

const caloriesNumberSchema = z.preprocess((value) => {
  if (typeof value === "string" && value.trim() !== "") return Number(value);
  return value;
}, z.number().int().min(0));

const goalCaloriesSchema = z.preprocess((value) => {
  if (typeof value === "string" && value.trim() !== "") return Number(value);
  return value;
}, z.number().int().min(1));

const logFoodInputSchema = {
  food: z.string().min(1),
  calories: caloriesNumberSchema,
  date: dateInputSchema.optional(),
  meal: z.enum(["breakfast", "lunch", "dinner", "snack"]).optional(),
  notes: z.string().min(1).max(500).optional(),
};

const listEntriesInputSchema = {
  date: dateInputSchema.optional(),
};

const deleteEntryInputSchema = {
  id: z.string().min(1),
};

const dailySummaryInputSchema = {
  date: dateInputSchema.optional(),
};

const setDailyGoalInputSchema = {
  calories: goalCaloriesSchema,
};

const logFoodArgsSchema = z.object(logFoodInputSchema);
const listEntriesArgsSchema = z.object(listEntriesInputSchema);
const deleteEntryArgsSchema = z.object(deleteEntryInputSchema);
const dailySummaryArgsSchema = z.object(dailySummaryInputSchema);
const setDailyGoalArgsSchema = z.object(setDailyGoalInputSchema);

let entries: CalorieEntry[] = [];
let nextId = 1;
let dailyGoalCalories: number | undefined;

function formatLocalDateYYYYMMDD(date: Date): string {
  const y = date.getFullYear();
  const m = String(date.getMonth() + 1).padStart(2, "0");
  const d = String(date.getDate()).padStart(2, "0");
  return `${y}-${m}-${d}`;
}

function summarizeForDate(date: string): DailySummary {
  const dayEntries = entries.filter((e) => e.date === date);
  const total = dayEntries.reduce((sum, e) => sum + e.calories, 0);
  const summary: DailySummary = {
    date,
    totalCalories: total,
    entriesCount: dayEntries.length,
  };

  if (typeof dailyGoalCalories === "number") {
    summary.goalCalories = dailyGoalCalories;
    summary.remainingCalories = Math.max(0, dailyGoalCalories - total);
  }

  return summary;
}

const replyWithEntries = (
  message?: string,
  payload?: { entries?: CalorieEntry[]; summary?: DailySummary }
): CalorieToolResponse => ({
  content: message ? [{ type: "text", text: message }] : [],
  structuredContent: {
    entries: payload?.entries ?? entries,
    ...(payload?.summary ? { summary: payload.summary } : {}),
  },
});

function createCalorieTrackerServer() {
  const server = new McpServer({ name: "calorie-tracker", version: "0.1.0" });

  server.registerTool(
    "log_food",
    {
      title: "Log food",
      description:
        "Logs a food entry with calories (optionally for a specific date/meal).",
      inputSchema: logFoodInputSchema,
    },
    async (args: unknown) => {
      const parsed = logFoodArgsSchema.safeParse(args);
      if (!parsed.success) return replyWithEntries("Invalid input.");

      const now = new Date();
      const date = parsed.data.date ?? formatLocalDateYYYYMMDD(now);
      const food = parsed.data.food.trim();
      const calories = parsed.data.calories;

      const entry: CalorieEntry = {
        id: `entry-${nextId++}`,
        food,
        calories,
        date,
        meal: parsed.data.meal,
        notes: parsed.data.notes,
        createdAt: now.toISOString(),
      };

      entries = [...entries, entry];
      const summary = summarizeForDate(date);
      return replyWithEntries(
        `Logged ${calories} calories for "${entry.food}" on ${date}.`,
        { summary }
      );
    }
  );

  server.registerTool(
    "delete_entry",
    {
      title: "Delete entry",
      description: "Deletes a logged food entry by id.",
      inputSchema: deleteEntryInputSchema,
    },
    async (args: unknown) => {
      const parsed = deleteEntryArgsSchema.safeParse(args);
      const id = parsed.success ? parsed.data.id : "";
      if (!id) return replyWithEntries("Missing entry id.");

      const entry = entries.find((e) => e.id === id);
      if (!entry) return replyWithEntries(`Entry ${id} was not found.`);

      entries = entries.filter((e) => e.id !== id);
      const summary = summarizeForDate(entry.date);
      return replyWithEntries(`Deleted entry "${entry.food}" (${id}).`, {
        summary,
      });
    }
  );

  server.registerTool(
    "list_entries",
    {
      title: "List entries",
      description: "Lists logged food entries (optionally filtered by date).",
      inputSchema: listEntriesInputSchema,
    },
    async (args: unknown) => {
      const parsed = listEntriesArgsSchema.safeParse(args);
      const date = parsed.success ? parsed.data.date : undefined;

      if (!date) return replyWithEntries("All entries:");

      const filtered = entries.filter((e) => e.date === date);
      return replyWithEntries(`Entries for ${date}:`, {
        entries: filtered,
        summary: summarizeForDate(date),
      });
    }
  );

  server.registerTool(
    "get_daily_summary",
    {
      title: "Get daily summary",
      description:
        "Returns total calories and entry count for a date (defaults to today).",
      inputSchema: dailySummaryInputSchema,
    },
    async (args: unknown) => {
      const parsed = dailySummaryArgsSchema.safeParse(args);
      const date =
        (parsed.success ? parsed.data.date : undefined) ??
        formatLocalDateYYYYMMDD(new Date());

      const summary = summarizeForDate(date);
      const goalText =
        typeof summary.goalCalories === "number"
          ? ` Goal ${summary.goalCalories}, remaining ${summary.remainingCalories}.`
          : "";
      return replyWithEntries(
        `Total for ${date}: ${summary.totalCalories} calories across ${summary.entriesCount} entries.${goalText}`,
        { summary, entries: entries.filter((e) => e.date === date) }
      );
    }
  );

  server.registerTool(
    "set_daily_goal",
    {
      title: "Set daily goal",
      description: "Sets a daily calorie goal (used by daily summaries).",
      inputSchema: setDailyGoalInputSchema,
    },
    async (args: unknown) => {
      const parsed = setDailyGoalArgsSchema.safeParse(args);
      const goal = parsed.success ? parsed.data.calories : undefined;
      if (typeof goal !== "number" || !Number.isFinite(goal)) {
        return replyWithEntries("Invalid goal calories.");
      }

      dailyGoalCalories = goal;
      const today = formatLocalDateYYYYMMDD(new Date());
      const summary = summarizeForDate(today);
      return replyWithEntries(`Set daily goal to ${goal} calories.`, { summary });
    }
  );

  return server;
}

const port = Number(process.env.PORT ?? 8787);
const MCP_PATH = "/mcp";

const httpServer = createServer(async (req, res) => {
  if (!req.url) {
    res.writeHead(400).end("Missing URL");
    return;
  }

  const url = new URL(req.url, `http://${req.headers.host ?? "localhost"}`);

  if (req.method === "OPTIONS" && url.pathname === MCP_PATH) {
    res.writeHead(204, {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "POST, GET, OPTIONS",
      "Access-Control-Allow-Headers": "content-type, mcp-session-id",
      "Access-Control-Expose-Headers": "Mcp-Session-Id",
    });
    res.end();
    return;
  }

  if (req.method === "GET" && url.pathname === "/") {
    res
      .writeHead(200, { "content-type": "text/plain" })
      .end("Calorie Tracker MCP server");
    return;
  }

  const MCP_METHODS = new Set(["POST", "GET", "DELETE"]);
  if (url.pathname === MCP_PATH && req.method && MCP_METHODS.has(req.method)) {
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Expose-Headers", "Mcp-Session-Id");

    const server = createCalorieTrackerServer();
    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: undefined, // stateless mode
      enableJsonResponse: true,
    });

    res.on("close", () => {
      transport.close();
      server.close();
    });

    try {
      await server.connect(transport);
      await transport.handleRequest(req, res);
    } catch (error) {
      console.error("Error handling MCP request:", error);
      if (!res.headersSent) {
        res.writeHead(500).end("Internal server error");
      }
    }
    return;
  }

  res.writeHead(404).end("Not Found");
});

httpServer.on("error", (error) => {
  const err = error as NodeJS.ErrnoException;
  if (err.code === "EADDRINUSE") {
    console.error(
      `Port ${port} is already in use. Try: PORT=8790 npm start (or set PORT in your environment).`
    );
    process.exit(1);
  }
  if (err.code === "EACCES") {
    console.error(
      `Permission denied binding to port ${port}. Try a different port: PORT=8790 npm start.`
    );
    process.exit(1);
  }
});

httpServer.listen(port, () => {
  console.log(
    `Calorie Tracker MCP server listening on http://localhost:${port}${MCP_PATH}`
  );
});


