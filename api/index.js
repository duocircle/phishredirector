// Vercel Functions entry point. vercel.json sends all paths to this function.
import { handleRequest } from '../src/redirector.js';

export default {
  fetch(request) {
    return handleRequest(request, process.env);
  },
};
