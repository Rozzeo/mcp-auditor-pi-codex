// Regression fixture excerpted from modelcontextprotocol/servers at
// 599dafc1054550a6eeb87a6545c1e1b03b3ca827, src/filesystem/index.ts.
// The two registerTool calls below are verbatim (upstream lines 248-316 and
// 615-642); only the unrelated registrations between them are omitted.
// The readFileAsBase64Stream helper (upstream lines 173-186) is included
// verbatim too, because read_media_file reaches the filesystem through it:
// without the helper there is nothing for capability propagation to resolve,
// and the fixture would silently stop testing the thing it exists to test.
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

// Reads a file as a stream of buffers, concatenates them, and then encodes
// the result to a Base64 string. This is a memory-efficient way to handle
// binary data from a stream before the final encoding.
async function readFileAsBase64Stream(filePath: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const stream = createReadStream(filePath);
    const chunks: Buffer[] = [];
    stream.on('data', (chunk) => {
      chunks.push(chunk as Buffer);
    });
    stream.on('end', () => {
      const finalBuffer = Buffer.concat(chunks);
      resolve(finalBuffer.toString('base64'));
    });
    stream.on('error', (err) => reject(err));
  });
}

server.registerTool(
  "read_media_file",
  {
    title: "Read Media File",
    description:
      "Read a file and return it as a base64-encoded content block with its MIME type. " +
      "Image and audio files are returned as image/audio content; any other file type is " +
      "returned as an embedded resource. Only works within allowed directories.",
    inputSchema: {
      path: z.string()
    },
    outputSchema: {
      content: z.array(z.union([
        z.object({
          type: z.enum(["image", "audio"]),
          data: z.string(),
          mimeType: z.string()
        }),
        z.object({
          type: z.literal("resource"),
          resource: z.object({
            uri: z.string(),
            // Optional, matching the SDK's BlobResourceContents shape (the handler always sets it).
            mimeType: z.string().optional(),
            blob: z.string()
          })
        })
      ]))
    },
    annotations: { readOnlyHint: true, openWorldHint: false }
  },
  async (args: z.infer<typeof ReadMediaFileArgsSchema>) => {
    const validPath = await validatePath(args.path);
    const extension = path.extname(validPath).toLowerCase();
    const mimeTypes: Record<string, string> = {
      ".png": "image/png",
      ".jpg": "image/jpeg",
      ".jpeg": "image/jpeg",
      ".gif": "image/gif",
      ".webp": "image/webp",
      ".bmp": "image/bmp",
      ".svg": "image/svg+xml",
      ".mp3": "audio/mpeg",
      ".wav": "audio/wav",
      ".ogg": "audio/ogg",
      ".flac": "audio/flac",
    };
    const mimeType = mimeTypes[extension] || "application/octet-stream";
    const data = await readFileAsBase64Stream(validPath);

    // Map the MIME type to a valid MCP content block. The spec only allows
    // text, image, audio, resource_link, and resource — so non-image/audio
    // binaries are returned as an embedded resource (NOT type:"blob", which the
    // SDK content-block union rejects on schema validation).
    const contentItem =
      mimeType.startsWith("image/")
        ? { type: "image" as const, data, mimeType }
        : mimeType.startsWith("audio/")
          ? { type: "audio" as const, data, mimeType }
          : {
              type: "resource" as const,
              resource: { uri: pathToFileURL(validPath).href, mimeType, blob: data }
            };
    return {
      content: [contentItem],
      structuredContent: { content: [contentItem] }
    };
  }
);

server.registerTool(
  "move_file",
  {
    title: "Move File",
    description:
      "Move or rename files and directories. Can move files between directories " +
      "and rename them in a single operation. If the destination exists, the " +
      "operation will fail. Works across different directories and can be used " +
      "for simple renaming within the same directory. Both source and destination must be within allowed directories.",
    inputSchema: {
      source: z.string(),
      destination: z.string()
    },
    outputSchema: { content: z.string() },
    annotations: { readOnlyHint: false, idempotentHint: false, destructiveHint: true, openWorldHint: false }
  },
  async (args: z.infer<typeof MoveFileArgsSchema>) => {
    const validSourcePath = await validatePath(args.source);
    const validDestPath = await validatePath(args.destination);
    await fs.rename(validSourcePath, validDestPath);
    const text = `Successfully moved ${args.source} to ${args.destination}`;
    const contentBlock = { type: "text" as const, text };
    return {
      content: [contentBlock],
      structuredContent: { content: text }
    };
  }
);
