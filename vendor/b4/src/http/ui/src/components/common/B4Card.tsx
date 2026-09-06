import { Card, CardProps } from "@mui/material";
import { colors, glows, radius, spacing } from "@design";

interface B4CardProps extends Omit<CardProps, "variant"> {
  variant?: "default" | "outlined" | "elevated";
}

export const B4Card = ({
  variant = "outlined",
  children,
  sx,
  ...props
}: B4CardProps) => {
  const variants = {
    default: {
      bgcolor: colors.background.paper,
      border: "none",
      p: 0,
    },
    outlined: {
      bgcolor: colors.background.paper,
      border: `1px solid ${colors.border.default}`,
      p: 0,
    },
    elevated: {
      bgcolor: colors.background.paper,
      border: `1px solid ${colors.border.default}`,
      boxShadow: glows.primary,
      p: spacing.md,
    },
  };

  return (
    <Card
      elevation={0}
      sx={{
        ...variants[variant],
        borderRadius: radius.md,
        ...sx,
      }}
      {...props}
    >
      {children}
    </Card>
  );
};
