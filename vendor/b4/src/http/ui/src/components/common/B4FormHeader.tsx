import { Grid, Divider } from "@mui/material";

export const B4FormHeader = ({
  label,
  ...props
}: {
  label: string;
  sx?: object;
}) => {
  return (
    <Grid size={{ xs: 12 }}>
      <Divider sx={{ ...props.sx }}>{label.toUpperCase()}</Divider>
    </Grid>
  );
};
