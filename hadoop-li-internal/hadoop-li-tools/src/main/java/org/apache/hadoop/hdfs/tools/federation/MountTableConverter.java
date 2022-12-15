package org.apache.hadoop.hdfs.tools.federation;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.apache.commons.cli.BasicParser;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.apache.commons.lang3.tuple.Pair;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.conf.Configured;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.GridMountTableConfiguration;
import org.apache.hadoop.fs.GridMountTableConfigurationFactory;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.hdfs.HdfsConfiguration;
import org.apache.hadoop.hdfs.server.federation.resolver.MountTableManager;
import org.apache.hadoop.hdfs.server.federation.resolver.MountTableResolver;
import org.apache.hadoop.hdfs.server.federation.resolver.RemoteLocation;
import org.apache.hadoop.hdfs.server.federation.router.RBFConfigKeys;
import org.apache.hadoop.hdfs.server.federation.router.RouterClient;
import org.apache.hadoop.hdfs.server.federation.store.protocol.AddMountTableEntryRequest;
import org.apache.hadoop.hdfs.server.federation.store.protocol.AddMountTableEntryResponse;
import org.apache.hadoop.hdfs.server.federation.store.protocol.GetMountTableEntriesRequest;
import org.apache.hadoop.hdfs.server.federation.store.protocol.GetMountTableEntriesResponse;
import org.apache.hadoop.hdfs.server.federation.store.protocol.RefreshMountTableEntriesRequest;
import org.apache.hadoop.hdfs.server.federation.store.protocol.RefreshMountTableEntriesResponse;
import org.apache.hadoop.hdfs.server.federation.store.protocol.RemoveMountTableEntryRequest;
import org.apache.hadoop.hdfs.server.federation.store.protocol.RemoveMountTableEntryResponse;
import org.apache.hadoop.hdfs.server.federation.store.protocol.UpdateMountTableEntryRequest;
import org.apache.hadoop.hdfs.server.federation.store.protocol.UpdateMountTableEntryResponse;
import org.apache.hadoop.hdfs.server.federation.store.records.MountTable;
import org.apache.hadoop.ipc.RPC;
import org.apache.hadoop.ipc.RemoteException;
import org.apache.hadoop.net.NetUtils;
import org.apache.hadoop.security.UserGroupInformation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * Router Admin Tool to convert Grid Dynamic Mount Table Json to {@link MountTable} records and update them in state store.
 * GridMountTable link will be converted to MountTable entry.
 * LinkFallback configuration should be used to set {@link RBFConfigKeys#DFS_ROUTER_DEFAULT_NAMESERVICE} for default
 * namespace of {@link MountTableResolver}
 */
public class MountTableConverter extends Configured {
  private static final Logger LOG = LoggerFactory.getLogger(MountTableConverter.class);
  static final String ROUTER_ADMIN_ADDRESS_FORMATTER = "%s-linkfs.grid.linkedin.com:%s";
  static final String RBF_NS_INDICATOR = "/THIS_IS_LINKFS";
  private final String rbfNsSuffix;
  private final String keytabPrincipal;
  private final String keytabPath;
  private final String clusterName;
  private final Path mountConfigPath;
  private final boolean dryRun;
  private final boolean removeOld;
  private RouterClient client;

  public static final Option MOUNT_CONFIG_PATH =
      new Option("mountConfigPath", true, "Hdfs path of the dynamic mount table config");

  public static final Option KEYTAB_PRINCIPAL =
      new Option("keytabPrincipal", true, "The principal of the provided keytab");

  public static final Option KEYTAB_PATH = new Option("keytabPath", true, "Path to the keytab to login with");

  public static final Option DRY_RUN = new Option("dryRun", false, "Whether to execute as a dry run");

  public static final Option REMOVE_OLD =
      new Option("removeOld", false, "Whether to remove mount points not in current mount table config");

  public static final Option RBF_NAMESPACE_SUFFIX = new Option("rbfNsSuffix", true, "RBF namespace suffix");

  public static final Option CLUSTER_NAME = new Option("cluster", true, "Cluster name used to construct router admin address");

  private static final Options OPTIONS = new Options().addOption(MOUNT_CONFIG_PATH)
      .addOption(KEYTAB_PRINCIPAL)
      .addOption(KEYTAB_PATH)
      .addOption(DRY_RUN)
      .addOption(REMOVE_OLD)
      .addOption(RBF_NAMESPACE_SUFFIX)
      .addOption(CLUSTER_NAME);

  public static void main(String[] args) throws Exception {
    Configuration conf = new HdfsConfiguration();

    try {
      CommandLineParser parser = new BasicParser();
      CommandLine commandLine = parser.parse(OPTIONS, args, false);

      String keytabPrincipal = commandLine.getOptionValue(KEYTAB_PRINCIPAL.getOpt());
      String keytabPath = commandLine.getOptionValue(KEYTAB_PATH.getOpt());
      String rbfNsSuffix = commandLine.getOptionValue(RBF_NAMESPACE_SUFFIX.getOpt());
      Path mountConfigPath = new Path(commandLine.getOptionValue(MOUNT_CONFIG_PATH.getOpt()));
      String clusterName = commandLine.getOptionValue(CLUSTER_NAME.getOpt());
      boolean dryRun = commandLine.hasOption(DRY_RUN.getOpt());
      boolean removeOld = commandLine.hasOption(REMOVE_OLD.getOpt());

      MountTableConverter adminTool =
          new MountTableConverter(conf, keytabPrincipal, keytabPath, mountConfigPath, dryRun, removeOld, rbfNsSuffix, clusterName);
      adminTool.initClient();
      adminTool.convert();
    } catch (ParseException ex) {
      HelpFormatter formatter = new HelpFormatter();
      formatter.printHelp("MountTableConverter", OPTIONS);
    }
  }

  public MountTableConverter(Configuration conf, String keytabPrincipal, String keytabPath, Path mountConfigPath,
      boolean dryRun, boolean removeOld, String rbfNsSuffix, String clusterName) {
    super(conf);
    this.keytabPrincipal = keytabPrincipal;
    this.keytabPath = keytabPath;
    this.mountConfigPath = mountConfigPath;
    this.dryRun = dryRun;
    this.removeOld = removeOld;
    this.rbfNsSuffix = rbfNsSuffix;
    this.clusterName = clusterName;
  }

  public void initClient() throws IOException {
    // Load client's minimum set of configurations to use kerberos
    Configuration.addDefaultResource("router-client-security.xml");

    if (this.clusterName != null) {
      // If clusterName is null, will fall back to use local configuration DFS_ROUTER_ADMIN_ADDRESS_KEY, if
      // DFS_ROUTER_ADMIN_ADDRESS_KEY is not set, will use DFS_ROUTER_ADMIN_ADDRESS_DEFAULT as router.admin-address.
      final String routerAdminAddr =
          String.format(ROUTER_ADMIN_ADDRESS_FORMATTER, this.clusterName, RBFConfigKeys.DFS_ROUTER_ADMIN_PORT_DEFAULT);
      getConf().set(RBFConfigKeys.DFS_ROUTER_ADMIN_ADDRESS_KEY, routerAdminAddr);
    }


    UserGroupInformation.loginUserFromKeytab(keytabPrincipal, new File(keytabPath).getAbsolutePath());
    try {
      String address = getConf().getTrimmed(RBFConfigKeys.DFS_ROUTER_ADMIN_ADDRESS_KEY,
          RBFConfigKeys.DFS_ROUTER_ADMIN_ADDRESS_DEFAULT);
      InetSocketAddress routerSocket = NetUtils.createSocketAddr(address);
      this.client = new RouterClient(routerSocket, getConf());
    } catch (RPC.VersionMismatch v) {
      LOG.error("RPC version mismatch between router client and server.");
      throw v;
    } catch (IOException e) {
      LOG.error("Cannot init router client to connect with router.");
      throw e;
    }
  }

  public void convert() throws Exception {
    if (dryRun) {
      LOG.info("[DRY RUN]");
    }

    LOG.info("Load grid mount table {}", mountConfigPath);

    Map<String, String> links = getLinks(this.mountConfigPath);
    try {
      Map<String, Pair<String, String>> mountTableLinks = convertLinks(links);
      List<MountTable> existingMountTable = getMountTableEntries();
      updateMountTable(existingMountTable, mountTableLinks, this.removeOld, this.dryRun);
    } catch (RemoteException e) {
      LOG.error("Router side exception, try later.");
      throw e;
    } finally {
      client.close();
    }
  }

  /**
   * Convert link entries to mountTableLinks, which is easier to be consumed by MountTableEntriesRequest.
   * @param links Valid link entries from the output configuration.
   * @return <srcPath, <destNs, destPath>>
   */
  public static Map<String, Pair<String, String>> convertLinks(Map<String, String> links) {
    Map<String, Pair<String, String>> mountTableLinks = new HashMap<>();
    for (String srcPath : links.keySet()) {
      String destNs = getDestNs(links.get(srcPath));
      String destPath = getDestPath(links.get(srcPath));
      mountTableLinks.put(srcPath, Pair.of(destNs, destPath));
    }
    return mountTableLinks;
  }

  /**
   * Update mountTable with converted links.
   * @param existingMountTable Current mountTable in state store.
   * @param mountTableLinks Converted links of mountConfig raw links.
   * @param removeOld Whether to remove mount points not in mountTableLinks.
   * @param dryRun Whether to execute as a dryRun.
   * @throws Exception If the mountTable cannot be updated.
   */
  public void updateMountTable(List<MountTable> existingMountTable, Map<String, Pair<String, String>> mountTableLinks,
      boolean removeOld, boolean dryRun) throws Exception {
    if (removeOld) {
      Set<String> gridSrcPaths = new HashSet<>(mountTableLinks.keySet());
      for (MountTable entry : existingMountTable) {
        if (!gridSrcPaths.contains(entry.getSourcePath())) {
          boolean removed = removeMount(entry.getSourcePath(), dryRun);
          if (!dryRun && !removed) {
            throw new Exception("Cannot remove mount point " + entry.getSourcePath());
          }
        }
      }
    }
    for (String srcPath : mountTableLinks.keySet()) {
      String destNs = mountTableLinks.get(srcPath).getKey();
      String destPath = mountTableLinks.get(srcPath).getValue();

      // Keep the old entry pointing to NN volume.
      if (destNs.endsWith(rbfNsSuffix)) {
        continue;
      }

      Map<String, String> destMap = new HashMap<String, String>() {{
        put(destNs, destPath);
      }};

      // Don't update if the entry does not change.
      if (existingMountTable.contains(MountTable.newInstance(srcPath, destMap))) {
        continue;
      }
      boolean added = addOrUpdateMount(srcPath, destNs, destPath, dryRun);
      if (!dryRun && !added) {
        throw new Exception(String.format("Cannot add mount point %s, %s -> %s", srcPath, destNs, destPath));
      }
    }
    if (!dryRun) {
      boolean refreshed = mountTableRefreshRequest(client.getMountTableManager());
      if (!refreshed) {
        throw new Exception("Cannot refresh mount table cache.");
      }
    }
  }

  /**
   * Add a mount table entry or update if it exists.
   * @param srcPath Src mount point.
   * @param destNs Destination name service
   * @param destPath Remote path.
   * @return If a mount table entry was added successfully.
   * @throws IOException If mount cannot be added/updated.
   */
  public boolean addOrUpdateMount(String srcPath, String destNs, String destPath, boolean dryRun) throws IOException {
    MountTableManager mountTableManager = client.getMountTableManager();
    MountTable existing = getMountEntry(srcPath, mountTableManager);

    Map<String, String> destMap = new HashMap<String, String>() {{
      put(destNs, destPath);
    }};

    if (existing == null) {
      MountTable newEntry = MountTable.newInstance(srcPath, destMap);
      // Validate this is a legal formatted MountEntry
      newEntry.validate();
      boolean added = false;
      if (!dryRun) {
        added = mountTableAddRequest(newEntry, mountTableManager);
        if (!added) {
          LOG.error("Cannot add mount point {}", srcPath);
        }
      }

      LOG.info("Added mount point {}; {}->{}", srcPath, destNs, destPath);
      return added;
    } else {
      List<RemoteLocation> existingDestinations = existing.getDestinations();
      List<RemoteLocation> remoteLocations = new ArrayList<>();
      remoteLocations.add(new RemoteLocation(destNs, destPath, srcPath));
      // DMT only supports single remote location for srcPath, so we replace remote locations with the newly set one.
      existing.setDestinations(remoteLocations);
      // Validate this is a legal formatted MountEntry
      existing.validate();
      boolean updated = false;
      if (!dryRun) {
        updated = mountTableUpdateRequest(existing, mountTableManager);
        if (!updated) {
          LOG.error("Cannot update mount point {}", srcPath);
        }
      }
      LOG.info("Updated existing mount point {}; from {} to [{}->{}]", srcPath, existingDestinations.toString(), destNs,
          destPath);

      return updated;
    }
  }

  /**
   * Remove a mount table entry.
   * @param srcPath Src mount point.
   * @return If a mount table entry was removed successfully.
   * @throws IOException If mount cannot be removed.
   */
  public boolean removeMount(String srcPath, boolean dryRun) throws IOException {
    MountTableManager mountTableManager = client.getMountTableManager();
    boolean removed = false;
    if (!dryRun) {
      removed = mountTableRemoveRequest(srcPath, mountTableManager);
      if (!removed) {
        LOG.error("Cannot remove mount point " + srcPath);
      }
    }
    LOG.info("Removed mount point " + srcPath);
    return removed;
  }

  /**
   * Get all mount table entries
   * @return List of mount table entries
   * @throws IOException If mount table entries cannot be obtained.
   */
  public List<MountTable> getMountTableEntries() throws IOException {
    MountTableManager mountTableManager = client.getMountTableManager();
    GetMountTableEntriesRequest request = GetMountTableEntriesRequest.newInstance("/");
    GetMountTableEntriesResponse response = mountTableManager.getMountTableEntries(request);
    return response.getEntries();
  }

  /**
   * Add mountConfig json to the {@link Configuration} and get valid link entries from the conf.
   * @param mountConfigPath mountConfig path.
   * @return links <srcPath, [scheme]://[volume_fqdn]:[scheme_port]/[target_path]>
   * @throws IOException If path cannot be opened
   */
  public Map<String, String> getLinks(Path mountConfigPath) throws IOException {
    final String DUMMY_VIEW = "DUMMY_VIEW";
    final int DUMMY_PORT = 9000;
    final String DUMMY_URI = "dummy:///";
    final String CONF_KEY_PREFIX = "fs.viewfs.mounttable." + DUMMY_VIEW + ".link.";
    final String LINK_FALLBACK_CONF_KEY = "fs.viewfs.mounttable." + DUMMY_VIEW + ".linkFallback";

    FileSystem fs = FileSystem.newInstance(mountConfigPath.toUri(), new Configuration());
    InputStream in = fs.open(mountConfigPath);

    Configuration output = new Configuration(false);
    GridMountTableConfiguration gridMountTableConfig =
        GridMountTableConfigurationFactory.create(GridMountTableConfiguration.Scheme.HDFS, in);
    gridMountTableConfig.addToConfiguration(output, GridMountTableConfiguration.Scheme.HDFS, DUMMY_PORT, DUMMY_VIEW,
        URI.create(DUMMY_URI));

    URI linkFallBackUri = URI.create(output.get(LINK_FALLBACK_CONF_KEY));
    Map<String, String> links = GridMountTableConfiguration.getValidLinks(output, CONF_KEY_PREFIX);
    // Add /THIS_IS_LINKFS -> defaultNs mount point to indicate using RBF
    links.put(RBF_NS_INDICATOR, linkFallBackUri.toString());
    return links;
  }

  /**
   * Get destination name service from conf value.
   * @param confVal Configuration entry value
   * @return Destination name service.
   */
  private static String getDestNs(String confVal) {
    URI uri = URI.create(confVal);
    String host = uri.getHost();
    String[] res = host.split("\\.");
    return res[0];
  }

  /**
   * Get destination path from conf value.
   * @param confVal Configuration entry value
   * @return Path in the destination namespace.
   */
  private static String getDestPath(String confVal) {
    URI uri = URI.create(confVal);
    return uri.getPath();
  }

  private MountTable getMountEntry(String srcPath, MountTableManager mountTableManager) throws IOException {
    List<MountTable> results = mountTableGetRequest(srcPath, mountTableManager);
    MountTable existingEntry = null;
    for (MountTable m : results) {
      if (m.getSourcePath().equals(srcPath)) {
        existingEntry = m;
      }
    }
    return existingEntry;
  }

  private List<MountTable> mountTableGetRequest(String srcPath, MountTableManager mountTableManager)
      throws IOException {
    GetMountTableEntriesRequest getRequest = GetMountTableEntriesRequest.newInstance(srcPath);
    GetMountTableEntriesResponse getResponse = mountTableManager.getMountTableEntries(getRequest);
    return getResponse.getEntries();
  }

  private boolean mountTableAddRequest(MountTable newEntry, MountTableManager mountTableManager) throws IOException {
    AddMountTableEntryRequest addRequest = AddMountTableEntryRequest.newInstance(newEntry);
    AddMountTableEntryResponse addResponse = mountTableManager.addMountTableEntry(addRequest);
    return addResponse.getStatus();
  }

  private boolean mountTableUpdateRequest(MountTable updatedEntry, MountTableManager mountTableManager)
      throws IOException {
    UpdateMountTableEntryRequest updateRequest = UpdateMountTableEntryRequest.newInstance(updatedEntry);
    UpdateMountTableEntryResponse updateResponse = mountTableManager.updateMountTableEntry(updateRequest);
    return updateResponse.getStatus();
  }

  private boolean mountTableRemoveRequest(String srcPath, MountTableManager mountTableManager) throws IOException {
    RemoveMountTableEntryRequest removeRequest = RemoveMountTableEntryRequest.newInstance(srcPath);
    RemoveMountTableEntryResponse removeResponse = mountTableManager.removeMountTableEntry(removeRequest);
    return removeResponse.getStatus();
  }

  /**
   * Should set {@link RBFConfigKeys#MOUNT_TABLE_CACHE_UPDATE}
   */
  private boolean mountTableRefreshRequest(MountTableManager mountTableManager) throws IOException {
    RefreshMountTableEntriesRequest refreshRequest = RefreshMountTableEntriesRequest.newInstance();
    RefreshMountTableEntriesResponse refreshResponse = mountTableManager.refreshMountTableEntries(refreshRequest);
    return refreshResponse.getResult();
  }
}
