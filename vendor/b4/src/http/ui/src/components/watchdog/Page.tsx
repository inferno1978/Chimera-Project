import { Container, Stack } from "@mui/material";
import { WatchdogMonitor } from "./Watchdog";

export function WatchdogPage() {
  return (
    <Container
      maxWidth={false}
      sx={{
        height: "100%",
        display: "flex",
        flexDirection: "column",
        overflow: "auto",
        py: 3,
      }}
    >
      <Stack spacing={3}>
        <WatchdogMonitor />
      </Stack>
    </Container>
  );
}
