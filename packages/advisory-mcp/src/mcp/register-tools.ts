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
