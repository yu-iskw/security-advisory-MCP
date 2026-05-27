import type { AdvisoryStore } from '../store/db.js';
import type { z } from 'zod';

export function toolResult(markdown: string, structured: unknown) {
  return {
    content: [
      {
        type: 'text' as const,
        text: `${markdown}\n\n\`\`\`json\n${JSON.stringify(structured, null, 2)}\n\`\`\``,
      },
    ],
  };
}

export interface LocalToolDefinition<TSchema extends z.ZodType> {
  name: string;
  description: string;
  inputSchema: TSchema;
  run: (store: AdvisoryStore, input: z.infer<TSchema>) => { markdown: string; structured: unknown };
}
