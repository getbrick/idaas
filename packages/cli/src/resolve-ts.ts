export async function resolve(specifier: string, _context: any, nextResolve: any): Promise<any> {
  try {
    return await nextResolve(specifier, _context);
  } catch (error) {
    if ((!specifier.startsWith(".") && !specifier.startsWith("/")) || !specifier.endsWith(".js")) throw error;
    return nextResolve(`${specifier.slice(0, -3)}.ts`, _context);
  }
}
