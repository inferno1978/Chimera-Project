import { TableCell, TableSortLabel } from "@mui/material";
import { colors } from "@design";

export type SortDirection = "asc" | "desc" | null;

interface SortableTableCellProps {
  label: string;
  active: boolean;
  direction: SortDirection;
  onSort: () => void;
  align?: "left" | "center" | "right";
}

export const SortableTableCell = ({
  label,
  active,
  direction,
  onSort,
  align = "left",
}: SortableTableCellProps) => {
  return (
    <TableCell
      sx={{
        bgcolor: colors.background.paper,
        color: colors.secondary,
        fontWeight: 600,
        borderBottom: `2px solid ${colors.border.default}`,
        cursor: "pointer",
        userSelect: "none",
        zIndex: 10,
        backgroundImage: "none !important",
        "&:hover": {
          borderBottomColor: colors.secondary,
          "& .MuiTableSortLabel-root": {
            color: `${colors.primary} !important`,
          },
        },
      }}
      align={align}
    >
      <TableSortLabel
        active={active}
        direction={active && direction ? direction : "asc"}
        onClick={onSort}
        sx={{
          color: `${colors.secondary} !important`,
          transition: "color 0.2s ease",
          "&.Mui-active": {
            color: `${colors.primary} !important`,
            "& .MuiTableSortLabel-icon": {
              color: `${colors.primary} !important`,
            },
          },
        }}
      >
        {label}
      </TableSortLabel>
    </TableCell>
  );
};
