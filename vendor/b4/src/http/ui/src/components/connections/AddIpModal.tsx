import { useCallback, useEffect, useState } from "react";
import {
  Button,
  Typography,
  List,
  ListItem,
  ListItemButton,
  ListItemText,
  ListItemIcon,
  Radio,
  Box,
  Stack,
} from "@mui/material";
import { AddIcon, DomainIcon } from "@b4.icons";
import { colors } from "@design";
import { B4SetConfig } from "@models/config";
import { SetSelector } from "@common/SetSelector";
import { asnStorage, stripPort } from "@utils";
import { clearAsnLookupCache } from "@hooks/useDomainActions";
import { B4Alert, B4Badge, B4Dialog } from "@b4.elements";
import { useTranslation } from "react-i18next";

interface IpInfo {
  ip: string;
  hostname?: string;
  org?: string;
  city?: string;
  region?: string;
  country?: string;
}

interface RipeNetworkInfo {
  asns: string[];
  prefix: string;
}

interface AddIpModalProps {
  open: boolean;
  ip: string;
  variants: string[];
  sets: B4SetConfig[];
  selected: string;
  ipInfoToken?: string;
  onClose: () => void;
  onSelectVariant: (variant: string | string[]) => void;
  onAdd: (setId: string, setName?: string) => void;
  onAddHostname?: (hostname: string) => void;
}

export const AddIpModal = ({
  open,
  ip,
  sets,
  variants: initialVariants,
  selected,
  ipInfoToken,
  onClose,
  onSelectVariant,
  onAdd,
  onAddHostname,
}: AddIpModalProps) => {
  const { t } = useTranslation();
  const [selectedSetId, setSelectedSetId] = useState<string>("");
  const [ipInfo, setIpInfo] = useState<IpInfo | null>(null);
  const [loadingInfo, setLoadingInfo] = useState(false);
  const [loadingPrefixes, setLoadingPrefixes] = useState(false);
  const [variants, setVariants] = useState<string[]>(initialVariants);
  const [asn, setAsn] = useState<string>("");
  const [prefixes, setPrefixes] = useState<string[]>([]);
  const [addMode, setAddMode] = useState<"single" | "all">("single");
  const [newSetName, setNewSetName] = useState<string>("");

  useEffect(() => {
    if (open) {
      setIpInfo(null);
      setAsn("");
      setPrefixes([]);
      setAddMode("single");
      setLoadingInfo(false);
      setLoadingPrefixes(false);
      setNewSetName("");
      setVariants(initialVariants);
      if (sets.length > 0) {
        const firstEnabled = sets.find((s) => s.enabled);
        setSelectedSetId(firstEnabled?.id ?? sets[0]?.id ?? "");
      }
    }
  }, [open, sets, initialVariants, ip]);

  useEffect(() => {
    if (!open) {
      setIpInfo(null);
      setAsn("");
      setPrefixes([]);
      setVariants(initialVariants);
      setAddMode("single");
      setLoadingInfo(false);
      setLoadingPrefixes(false);
      setNewSetName("");
      onSelectVariant(initialVariants[0] || "");
    }
  }, [open, initialVariants, onSelectVariant]);

  const loadIpInfo = async () => {
    setLoadingInfo(true);
    try {
      const cleanIp = stripPort(ip);
      const response = await fetch(
        `/api/integration/ipinfo?ip=${encodeURIComponent(cleanIp)}`
      );
      if (response.ok) {
        const data = (await response.json()) as IpInfo;
        setIpInfo(data);

        // Extract ASN from org field (e.g., "AS13335 Cloudflare, Inc.")
        if (data.org) {
          const asnMatch = /AS(\d+)/.exec(data.org);
          if (asnMatch) {
            setAsn(asnMatch[1]);
          }
        }
      }
    } catch (error) {
      console.error("Failed to load IP info:", error);
    } finally {
      setLoadingInfo(false);
    }
  };

  const loadRipeNetworkInfo = async () => {
    setLoadingInfo(true);
    try {
      const cleanIp = stripPort(ip);
      const response = await fetch(
        `/api/integration/ripestat?ip=${encodeURIComponent(cleanIp)}`
      );
      if (response.ok) {
        const data = (await response.json()) as { data: RipeNetworkInfo };
        const networkData = data.data;
        if (networkData.asns && networkData.asns.length > 0) {
          setAsn(networkData.asns[0]);
          setIpInfo({
            ip: cleanIp,
            org: `AS${networkData.asns[0]}`,
          });
        }
      }
    } catch (error) {
      console.error("Failed to load RIPE network info:", error);
    } finally {
      setLoadingInfo(false);
    }
  };

  const loadRipePrefixes = useCallback(async () => {
    if (!asn) return;

    setLoadingPrefixes(true);
    try {
      const response = await fetch(
        `/api/integration/ripestat/asn?asn=${encodeURIComponent(asn)}`
      );
      if (response.ok) {
        const data = (await response.json()) as {
          data: { prefixes: Array<{ prefix: string }> };
        };
        const loadedPrefixes = data.data.prefixes.map((p) => p.prefix);
        setPrefixes(loadedPrefixes);
        setAddMode("all");
        onSelectVariant(loadedPrefixes);
        void asnStorage.addAsn(asn, ipInfo?.org || `AS${asn}`, loadedPrefixes);
        clearAsnLookupCache();
      }
    } catch (error) {
      console.error("Failed to load RIPE prefixes:", error);
    } finally {
      setLoadingPrefixes(false);
    }
  }, [asn, ipInfo?.org, onSelectVariant]);

  const handleAdd = () => {
    onAdd(selectedSetId, newSetName);
  };

  useEffect(() => {
    if (asn && open) {
      void loadRipePrefixes();
    }
  }, [asn, loadRipePrefixes, open]);

  const handleAddHostname = () => {
    if (ipInfo?.hostname && onAddHostname) {
      onAddHostname(ipInfo.hostname);
      onClose();
    }
  };

  return (
    <B4Dialog
      title={t("connections.addIp.title")}
      icon={<DomainIcon />}
      open={open}
      onClose={onClose}
      maxWidth="md"
      actions={
        <>
          <Button onClick={onClose}>{t("core.cancel")}</Button>
          <Box sx={{ flex: 1 }} />
          <Button
            onClick={handleAdd}
            variant="contained"
            startIcon={<AddIcon />}
            disabled={!selected && prefixes.length === 0}
          >
            {addMode === "all" && prefixes.length > 0
              ? t("connections.addIp.addAllPrefixes", { count: prefixes.length })
              : t("connections.addIp.addIpCidr")}
          </Button>
        </>
      }
    >
      <>
        <B4Alert severity="info" sx={{ mb: 2 }}>
          {t("connections.addIp.alert")}
        </B4Alert>

        <Box sx={{ mb: 3 }}>
          {ipInfo ? (
            <>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                {t("connections.addIp.originalIp")} <B4Badge label={ip} color="secondary" />
              </Typography>
              <Box
                sx={{
                  p: 2,
                  bgcolor: colors.background.dark,
                  borderRadius: 1,
                  border: `1px solid ${colors.border.default}`,
                }}
              >
                <Stack direction="row" spacing={2} alignItems="center">
                  <Box sx={{ flex: 1 }}>
                    {ipInfo.org && (
                      <Typography variant="body2" color="text.primary">
                        <strong>{t("connections.addIp.org")}</strong> {ipInfo.org}
                      </Typography>
                    )}
                    {ipInfo.hostname && (
                      <Typography variant="body2" color="text.secondary">
                        <strong>{t("connections.addIp.hostname")}</strong> {ipInfo.hostname}
                      </Typography>
                    )}
                    {(ipInfo.city || ipInfo.region || ipInfo.country) && (
                      <Typography variant="body2" color="text.secondary">
                        <strong>{t("connections.addIp.location")}</strong>{" "}
                        {[ipInfo.city, ipInfo.region, ipInfo.country]
                          .filter(Boolean)
                          .join(", ")}
                      </Typography>
                    )}
                    {asn && loadingPrefixes && (
                      <Typography
                        variant="body2"
                        color={colors.secondary}
                        sx={{ mt: 1 }}
                      >
                        {t("core.loadingPrefixes", { asn })}
                      </Typography>
                    )}
                  </Box>
                  {ipInfo.hostname && onAddHostname && (
                    <Button size="small" onClick={handleAddHostname}>
                      {t("core.addHostname")}
                    </Button>
                  )}
                </Stack>
              </Box>
            </>
          ) : (
            <Stack direction="row" spacing={2} alignItems="center">
              <Typography variant="body2" color="text.secondary">
                {t("connections.addIp.originalIp")} <B4Badge label={ip} color="primary" />
              </Typography>
              <Box sx={{ flex: 1 }} />
              {ipInfoToken && (
                <Button
                  variant="outlined"
                  size="small"
                  onClick={() => void loadIpInfo()}
                  disabled={loadingInfo}
                >
                  {loadingInfo ? t("core.loading") : t("connections.addIp.enrichWithIpInfo")}
                </Button>
              )}
              <Button
                variant="outlined"
                size="small"
                onClick={() => void loadRipeNetworkInfo()}
                disabled={loadingInfo}
              >
                {loadingInfo ? t("core.loading") : t("connections.addIp.loadNetworkInfo")}
              </Button>
            </Stack>
          )}
        </Box>

        {sets.length > 0 && (
          <SetSelector
            sets={sets}
            value={selectedSetId}
            onChange={(setId, name) => {
              setSelectedSetId(setId);
              if (name) setNewSetName(name);
            }}
          />
        )}

        {prefixes.length > 0 ? (
          <>
            <Typography
              variant="body2"
              color="text.secondary"
              sx={{ mb: 1, mt: 2 }}
            >
              {t("connections.addIp.loadedPrefixes", { count: prefixes.length, asn })}
            </Typography>
            <Stack direction="row" spacing={1} sx={{ mb: 2 }}>
              <B4Badge
                label={t("connections.addIp.addIpOnly", { ip })}
                onClick={() => {
                  setAddMode("single");
                  onSelectVariant(initialVariants[0]);
                }}
                color="secondary"
                variant="outlined"
              />
              <B4Badge
                label={t("connections.addIp.addAllPrefixesBadge", { count: prefixes.length })}
                onClick={() => {
                  setAddMode("all");
                  onSelectVariant(prefixes);
                }}
                variant="outlined"
                color="primary"
              />
            </Stack>
          </>
        ) : (
          <>
            <Typography
              variant="body2"
              color="text.secondary"
              sx={{ mb: 1, mt: 2 }}
            >
              {t("connections.addIp.cidrVariants")}
            </Typography>
            <List sx={{ maxHeight: 400, overflow: "auto" }}>
              {variants.map((variant) => (
                <ListItem key={variant} disablePadding>
                  <ListItemButton
                    onClick={() => onSelectVariant(variant)}
                    selected={selected === variant}
                    sx={{
                      borderRadius: 1,
                      mb: 0.5,
                      "&.Mui-selected": {
                        bgcolor: colors.accent.primary,
                        "&:hover": { bgcolor: colors.accent.primaryHover },
                      },
                    }}
                  >
                    <ListItemIcon>
                      <Radio
                        checked={selected === variant}
                        sx={{
                          color: colors.border.default,
                          "&.Mui-checked": { color: colors.primary },
                        }}
                      />
                    </ListItemIcon>
                    <ListItemText
                      primary={variant}
                      secondary={(() => {
                        const [, cidr] = variant.split("/");
                        if (cidr === "32" || cidr === "128") return t("connections.addIp.singleIp");
                        if (cidr === "24") return t("connections.addIp.subnet256");
                        if (cidr === "16") return t("connections.addIp.network65k");
                        if (cidr === "8") return t("connections.addIp.classA");
                        if (cidr === "64") return t("connections.addIp.ipv6Subnet");
                        if (cidr === "48") return t("connections.addIp.ipv6Site");
                        return t("connections.addIp.ipv6IspRange");
                      })()}
                    />
                  </ListItemButton>
                </ListItem>
              ))}
            </List>
          </>
        )}
      </>
    </B4Dialog>
  );
};
