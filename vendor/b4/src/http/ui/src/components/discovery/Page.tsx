import { Container, Stack } from "@mui/material";
import { DiscoveryRunner } from "./Discovery";

export function DiscoveryPage() {
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
        <DiscoveryRunner />
      </Stack>
    </Container>
  );
}
