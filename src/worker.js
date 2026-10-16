// Cloudflare Workers entry point.
import { handleRequest } from './redirector.js';

export default {
  fetch(request, env) {
    return handleRequest(request, env);
  },
};
