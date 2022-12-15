package org.apache.hadoop.hdfs.tools.federation;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.apache.commons.lang3.tuple.Pair;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.hdfs.server.federation.MiniRouterDFSCluster.RouterContext;
import org.apache.hadoop.hdfs.server.federation.RouterConfigBuilder;
import org.apache.hadoop.hdfs.server.federation.StateStoreDFSCluster;
import org.apache.hadoop.hdfs.server.federation.resolver.MultipleDestinationMountTableResolver;
import org.apache.hadoop.hdfs.server.federation.resolver.RemoteLocation;
import org.apache.hadoop.hdfs.server.federation.router.RBFConfigKeys;
import org.apache.hadoop.hdfs.server.federation.router.Router;
import org.apache.hadoop.hdfs.server.federation.router.RouterClient;
import org.apache.hadoop.hdfs.server.federation.store.StateStoreService;
import org.apache.hadoop.hdfs.server.federation.store.impl.MountTableStoreImpl;
import org.apache.hadoop.hdfs.server.federation.store.protocol.AddMountTableEntryRequest;
import org.apache.hadoop.hdfs.server.federation.store.protocol.GetMountTableEntriesRequest;
import org.apache.hadoop.hdfs.server.federation.store.protocol.GetMountTableEntriesResponse;
import org.apache.hadoop.hdfs.server.federation.store.protocol.RemoveMountTableEntryRequest;
import org.apache.hadoop.hdfs.server.federation.store.records.MountTable;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import static org.apache.hadoop.hdfs.tools.federation.MountTableConverter.*;
import static org.junit.Assert.*;


public class TestMountTableConverter {
  private static StateStoreDFSCluster dfsCluster;
  private static RouterContext routerContext;
  private static StateStoreService stateStore;

  private static MountTableConverter converter;
  private static RouterClient client;

  @BeforeClass
  public static void clusterSetup() throws Exception {
    Configuration conf = new RouterConfigBuilder().stateStore().admin().rpc().safemode().metrics().build();
    dfsCluster = new StateStoreDFSCluster(false, 1, MultipleDestinationMountTableResolver.class);
    dfsCluster.addRouterOverrides(conf);
    dfsCluster.startRouters();

    routerContext = dfsCluster.getRandomRouter();
    client = routerContext.getAdminClient();
    Router router = routerContext.getRouter();
    stateStore = router.getStateStore();

    Configuration routerConf = new Configuration();
    InetSocketAddress routerSocket = router.getAdminServerAddress();
    // clusterName is null, we use routerSocket to overwrite DFS_ROUTER_ADMIN_ADDRESS_KEY for unit tests.
    routerConf.setSocketAddr(RBFConfigKeys.DFS_ROUTER_ADMIN_ADDRESS_KEY, routerSocket);
    converter =
        new MountTableConverter(routerConf, "hdfs", "/dummy.headless.keytab", new Path("file:///dummy.json"), true,
            false, "fed", null);
    converter.initClient();
  }

  @AfterClass
  public static void tearDownCluster() {
    dfsCluster.stopRouter(routerContext);
    dfsCluster.shutdown();
    dfsCluster = null;
  }

  @Test
  public void testGetRouterAdminAddr() throws IOException {
    String clusterName = "cluster01";
    String expectedRouterAdminAddr =
        String.format(ROUTER_ADMIN_ADDRESS_FORMATTER, clusterName, RBFConfigKeys.DFS_ROUTER_ADMIN_PORT_DEFAULT);
    MountTableConverter remoteConverter =
        new MountTableConverter(new Configuration(), "hdfs", "/dummy.headless.keytab", new Path("file:///dummy.json"),
            true, false, "fed", clusterName);

    remoteConverter.initClient();
    assertEquals(expectedRouterAdminAddr,
        remoteConverter.getConf().getTrimmed(RBFConfigKeys.DFS_ROUTER_ADMIN_ADDRESS_KEY));
  }

  @Test
  public void testGetLinks() throws Exception {
    String expectedSrc1 = "/data/databases";
    String expectedSrc2 = "/tmp";
    String mountConfig = "mount-config-mock.json";

    Map<String, String> expectedLinks = new HashMap<String, String>() {{
      put(expectedSrc1, "hdfs://ns02.example.com:9000/data/databases");
      put(expectedSrc2, "hdfs://ns01.example.com:9000/foo/bar");
      put(RBF_NS_INDICATOR, "hdfs://ns01.example.com:9000/");
    }};

    ClassLoader classLoader = this.getClass().getClassLoader();
    Path configPath = new Path(classLoader.getResource(mountConfig).toURI());
    Map<String, String> actualLinks = converter.getLinks(configPath);
    assertEquals(expectedLinks, actualLinks);
  }

  @Test
  public void testConvertLinks() {
    String expectedNs1 = "ns-fed";
    String expectedNs2 = "ns01";
    String expectedSrc1 = "/data/databases9000";
    String expectedSrc2 = "/tmp";
    String expectedDest2 = "/foo/bar";

    Map<String, String> links = new HashMap<String, String>() {{
      put(expectedSrc1, "hdfs://ns-fed.example.com:9000/data/databases9000");
      put(expectedSrc2, "hdfs://ns01.example.com:9000/foo/bar");
    }};

    Map<String, Pair<String, String>> expectedMountTableLinks = new HashMap<String, Pair<String, String>>() {{
      put(expectedSrc1, Pair.of(expectedNs1, expectedSrc1));
      put(expectedSrc2, Pair.of(expectedNs2, expectedDest2));
    }};

    Map<String, Pair<String, String>> actualMountTableLinks = MountTableConverter.convertLinks(links);
    assertEquals(expectedMountTableLinks, actualMountTableLinks);
  }

  @Test
  public void testUpdateMountTable() throws Exception {
    String ns1 = "ns0";
    String ns2 = "ns1";
    String srcPath1 = "/foo";
    String destPath1 = srcPath1 + "-updated";
    String srcPath2 = "/newPath";

    List<MountTable> existingMountTable = createTestMountTable();
    List<MountTable> expectedUpdatedMountTable = new ArrayList<>(existingMountTable);
    Map<String, String> originalDestMap = new HashMap<String, String>() {{
      put(ns1, srcPath1);
    }};
    Map<String, String> destMap1 = new HashMap<String, String>() {{
      put(ns1, destPath1);
    }};
    Map<String, String> destMap2 = new HashMap<String, String>() {{
      put(ns2, srcPath2);
    }};
    expectedUpdatedMountTable.remove(MountTable.newInstance(srcPath1, originalDestMap));
    expectedUpdatedMountTable.add(MountTable.newInstance(srcPath1, destMap1));
    expectedUpdatedMountTable.add(MountTable.newInstance(srcPath2, destMap2));

    Map<String, Pair<String, String>> mountTableLinks = new HashMap<String, Pair<String, String>>() {{
      put(srcPath1, Pair.of(ns1, destPath1));
      put(srcPath2, Pair.of(ns2, srcPath2));
    }};
    converter.updateMountTable(existingMountTable, mountTableLinks, false, false);
    stateStore.loadCache(MountTableStoreImpl.class, true);
    List<MountTable> updatedMountTable = converter.getMountTableEntries();
    assertEquals(3, updatedMountTable.size());
    assertEquals(expectedUpdatedMountTable, updatedMountTable);
  }

  @Test
  public void testUpdateMountTableRemoveOld() throws Exception {
    String ns = "ns0";
    String srcPath = "/newPath";

    List<MountTable> existingMountTable = createTestMountTable();
    List<MountTable> expectedUpdatedMountTable = new ArrayList<>();
    Map<String, String> destMap = new HashMap<String, String>() {{
      put(ns, srcPath);
    }};

    expectedUpdatedMountTable.add(MountTable.newInstance(srcPath, destMap));

    Map<String, Pair<String, String>> mountTableLinks = new HashMap<String, Pair<String, String>>() {{
      put(srcPath, Pair.of(ns, srcPath));
    }};
    converter.updateMountTable(existingMountTable, mountTableLinks, true, false);
    stateStore.loadCache(MountTableStoreImpl.class, true);
    List<MountTable> updatedMountTable = converter.getMountTableEntries();
    assertEquals(1, updatedMountTable.size());
    assertEquals(expectedUpdatedMountTable, updatedMountTable);
  }

  @Test
  public void testUpdateMountTableDryRun() throws Exception {
    String ns = "ns0";
    String srcPath = "/newPath";

    List<MountTable> existingMountTable = createTestMountTable();
    Map<String, Pair<String, String>> mountTableLinks = new HashMap<String, Pair<String, String>>() {{
      put(srcPath, Pair.of(ns, srcPath));
    }};
    converter.updateMountTable(existingMountTable, mountTableLinks, false, true);
    stateStore.loadCache(MountTableStoreImpl.class, true);
    List<MountTable> updatedMountTable = converter.getMountTableEntries();
    assertEquals(2, updatedMountTable.size());
    assertEquals(existingMountTable, updatedMountTable);
  }

  @Test
  public void testAddOrUpdateMount() throws Exception {
    boolean isDryRun = false;
    String srcPath = "/testAdd";
    String destPath = "/foo";
    String ns = "ns0";

    assertTrue(converter.addOrUpdateMount(srcPath, ns, destPath, isDryRun));
    stateStore.loadCache(MountTableStoreImpl.class, true);

    GetMountTableEntriesRequest getRequest = GetMountTableEntriesRequest.newInstance(srcPath);
    GetMountTableEntriesResponse getResponse = client.getMountTableManager().getMountTableEntries(getRequest);
    MountTable mountTable = getResponse.getEntries().get(0);

    List<RemoteLocation> destinations = mountTable.getDestinations();
    assertEquals(1, destinations.size());
    assertEquals(srcPath, mountTable.getSourcePath());
    assertEquals(ns, destinations.get(0).getNameserviceId());
    assertEquals(destPath, destinations.get(0).getDest());

    destPath = destPath + "-updated";

    assertTrue(converter.addOrUpdateMount(srcPath, ns, destPath, isDryRun));
    stateStore.loadCache(MountTableStoreImpl.class, true);

    getResponse = client.getMountTableManager().getMountTableEntries(getRequest);
    mountTable = getResponse.getEntries().get(0);
    destinations = mountTable.getDestinations();
    assertEquals(1, destinations.size());
    assertEquals(srcPath, mountTable.getSourcePath());
    assertEquals(ns, destinations.get(0).getNameserviceId());
    assertEquals(destPath, destinations.get(0).getDest());
  }

  @Test
  public void testRemoveMount() throws Exception {
    boolean isDryRun = false;
    String srcPath = "/testRemove";
    String destPath = "/foo";
    String ns = "ns0";

    assertTrue(converter.addOrUpdateMount(srcPath, ns, destPath, isDryRun));
    stateStore.loadCache(MountTableStoreImpl.class, true);

    GetMountTableEntriesRequest getRequest = GetMountTableEntriesRequest.newInstance(srcPath);
    GetMountTableEntriesResponse getResponse = client.getMountTableManager().getMountTableEntries(getRequest);
    MountTable mountTable = getResponse.getEntries().get(0);

    assertEquals(srcPath, mountTable.getSourcePath());
    assertTrue(converter.removeMount(srcPath, isDryRun));
    stateStore.loadCache(MountTableStoreImpl.class, true);

    getResponse = client.getMountTableManager().getMountTableEntries(getRequest);
    assertEquals(0, getResponse.getEntries().size());

    String invalidSrcPath = "/invalidPath";
    assertFalse(converter.removeMount(invalidSrcPath, isDryRun));
  }

  @Test
  public void testGetMountTableEntries() throws Exception {
    boolean isDryRun = false;
    String ns = "ns0";
    String srcPath1 = "/dir1";
    String srcPath2 = "/dir1/subdir";
    String destPath1 = "/foo";
    String destPath2 = "/bar";

    Map<String, String> destMap1 = new HashMap<>();
    destMap1.put(ns, destPath1);
    Map<String, String> destMap2 = new HashMap<>();
    destMap2.put(ns, destPath2);
    Set<MountTable> expected = new HashSet<>();
    expected.add(MountTable.newInstance(srcPath1, destMap1));
    expected.add(MountTable.newInstance(srcPath2, destMap2));

    GetMountTableEntriesRequest getRequest = GetMountTableEntriesRequest.newInstance("/");
    GetMountTableEntriesResponse getResponse = client.getMountTableManager().getMountTableEntries(getRequest);
    for (MountTable entry : getResponse.getEntries()) {
      assertTrue(converter.removeMount(entry.getSourcePath(), isDryRun));
    }
    stateStore.loadCache(MountTableStoreImpl.class, true);

    assertTrue(converter.addOrUpdateMount(srcPath1, ns, destPath1, isDryRun));
    assertTrue(converter.addOrUpdateMount(srcPath2, ns, destPath2, isDryRun));
    stateStore.loadCache(MountTableStoreImpl.class, true);

    List<MountTable> entries = converter.getMountTableEntries();
    assertEquals(2, entries.size());
    assertEquals(expected, new HashSet<>(entries));
  }

  @Test
  public void testAddOrUpdateMountDryRun() throws Exception {
    boolean isDryRun = true;
    String srcPath = "/testAddDryRun";
    String destPath = "/foo";
    String ns = "ns0";

    assertFalse(converter.addOrUpdateMount(srcPath, ns, destPath, isDryRun));
    stateStore.loadCache(MountTableStoreImpl.class, true);

    GetMountTableEntriesRequest getRequest = GetMountTableEntriesRequest.newInstance(srcPath);
    GetMountTableEntriesResponse getResponse = client.getMountTableManager().getMountTableEntries(getRequest);
    assertEquals(0, getResponse.getEntries().size());
  }

  @Test
  public void testRemoveMountDryRun() throws Exception {
    boolean isDryRun = true;
    String srcPath = "/testRemoveDryRun";
    String destPath = "/foo";
    String ns = "ns0";

    assertTrue(converter.addOrUpdateMount(srcPath, ns, destPath, false));
    stateStore.loadCache(MountTableStoreImpl.class, true);

    assertFalse(converter.removeMount(srcPath, isDryRun));
    stateStore.loadCache(MountTableStoreImpl.class, true);

    GetMountTableEntriesRequest getRequest = GetMountTableEntriesRequest.newInstance(srcPath);
    GetMountTableEntriesResponse getResponse = client.getMountTableManager().getMountTableEntries(getRequest);
    assertEquals(1, getResponse.getEntries().size());
  }

  @Test
  public void testRbfIndicator() throws Exception {
    String mountConfig = "mount-config-mock.json";
    Map<String, String> destMap = new HashMap<String, String>() {{
      put("ns01", "/");
    }};

    Path configPath = new Path(this.getClass().getClassLoader().getResource(mountConfig).toURI());
    Map<String, String> links = converter.getLinks(configPath);
    Map<String, Pair<String, String>> mountTableLinks = MountTableConverter.convertLinks(links);

    converter.updateMountTable(converter.getMountTableEntries(), mountTableLinks, true, false);
    stateStore.loadCache(MountTableStoreImpl.class, true);

    List<MountTable> updatedMountTable = converter.getMountTableEntries();
    assertEquals(3, updatedMountTable.size());
    assertTrue(updatedMountTable.contains(MountTable.newInstance(RBF_NS_INDICATOR, destMap)));
  }

  private List<MountTable> createTestMountTable() throws IOException {
    String ns1 = "ns0";
    String srcPath1 = "/foo";
    String ns2 = "ns1";
    String srcPath2 = "/bar";
    Map<String, String> destMap1 = new HashMap<String, String>() {{
      put(ns1, srcPath1);
    }};
    Map<String, String> destMap2 = new HashMap<String, String>() {{
      put(ns2, srcPath2);
    }};

    GetMountTableEntriesRequest getRequest = GetMountTableEntriesRequest.newInstance("/");
    GetMountTableEntriesResponse getResponse = client.getMountTableManager().getMountTableEntries(getRequest);
    List<MountTable> existingMountTable = getResponse.getEntries();

    for (MountTable entry : existingMountTable) {
      RemoveMountTableEntryRequest removeRequest = RemoveMountTableEntryRequest.newInstance(entry.getSourcePath());
      client.getMountTableManager().removeMountTableEntry(removeRequest);
    }

    AddMountTableEntryRequest addRequest =
        AddMountTableEntryRequest.newInstance(MountTable.newInstance(srcPath1, destMap1));
    client.getMountTableManager().addMountTableEntry(addRequest);
    addRequest.setEntry(MountTable.newInstance(srcPath2, destMap2));
    client.getMountTableManager().addMountTableEntry(addRequest);

    stateStore.loadCache(MountTableStoreImpl.class, true);

    getRequest = GetMountTableEntriesRequest.newInstance("/");
    getResponse = client.getMountTableManager().getMountTableEntries(getRequest);
    existingMountTable = getResponse.getEntries();
    assertEquals(2, existingMountTable.size());

    return existingMountTable;
  }
}
