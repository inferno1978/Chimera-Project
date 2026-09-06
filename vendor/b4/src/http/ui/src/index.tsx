import { createRoot } from "react-dom/client";
import { BrowserRouter } from "react-router";
import "./i18n";
import App from "./App";
import { AuthProvider } from "./context/AuthProvider";
import { WebSocketProvider } from "./context/B4WsProvider";
import { AiStatusProvider } from "./context/AiStatusProvider";

const root = createRoot(document.getElementById("root")!);
root.render(
  <BrowserRouter>
    <AuthProvider>
      <WebSocketProvider>
        <AiStatusProvider>
          <App />
        </AiStatusProvider>
      </WebSocketProvider>
    </AuthProvider>
  </BrowserRouter>,
);
