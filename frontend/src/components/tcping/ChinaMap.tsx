import React, { useEffect, useMemo, useRef, useState } from 'react';
import * as echarts from 'echarts/core';
import { MapChart } from 'echarts/charts';
import { TooltipComponent } from 'echarts/components';
import { CanvasRenderer } from 'echarts/renderers';
import { carriers, latencyColor, median, Target } from './types';
import { connectionSummary, provinceSummary, summaryState } from './model';

echarts.use([MapChart, TooltipComponent, CanvasRenderer]);
const fullName = (name: string) => ({ 内蒙古: '内蒙古自治区', 广西: '广西壮族自治区', 西藏: '西藏自治区', 宁夏: '宁夏回族自治区', 新疆: '新疆维吾尔自治区', 北京: '北京市', 天津: '天津市', 上海: '上海市', 重庆: '重庆市' }[name] || name + '省');
type MapFeature = { properties?: { name?: string }; [key: string]: unknown };
type MapData = { features: MapFeature[]; [key: string]: unknown };
const registeredMaps = new Set<string>();
const chinaMapUrl = new URL('../../china-map.json', import.meta.url).href;
let mapDataPromise: Promise<MapData> | null = null;
function loadMapData() {
  if (!mapDataPromise) {
    mapDataPromise = fetch(chinaMapUrl, { credentials: 'same-origin' }).then(response => {
      if (!response.ok) throw new Error(`Map data request failed (${response.status})`);
      return response.json() as Promise<MapData>;
    }).then(mapData => {
      echarts.registerMap('narwhal-china', mapData as unknown as Parameters<typeof echarts.registerMap>[1]);
      registeredMaps.add('narwhal-china');
      return mapData;
    });
  }
  return mapDataPromise;
}
function mapForProvince(province: string, mapData: MapData) {
  if (!province) return 'narwhal-china';
  const name = fullName(province), feature = mapData.features.find(item => item.properties?.name === name);
  if (!feature) return 'narwhal-china';
  const mapName = `narwhal-province-${name}`;
  if (!registeredMaps.has(mapName)) {
    echarts.registerMap(mapName, { ...mapData, features: [feature] } as unknown as Parameters<typeof echarts.registerMap>[1]);
    registeredMaps.add(mapName);
  }
  return mapName;
}
const escape = (s: string) => s.replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]!));

export const ChinaMap: React.FC<{ nodes: Target[]; province: string; carrier: string; status: string; onSelect: (value: string) => void }> = ({ nodes, province, carrier, status, onSelect }) => {
  const el = useRef<HTMLDivElement>(null);
  const chart = useRef<echarts.ECharts>();
  const [mapData, setMapData] = useState<MapData | null>(null);
  const callback = useRef(onSelect); callback.current = onSelect;
  const mapName = mapData ? mapForProvince(province, mapData) : '';
  const data = useMemo(() => [...[...new Set(nodes.map(n => n.province))].map(p => {
    const { rows, completed, good, value, filteredOut } = provinceSummary(nodes, p, { province, carrier, status });
    const summary = connectionSummary(rows);
    return { name: fullName(p), short: p, value, completed, total: rows.length, good, filteredOut,
      label: { show: false },
      itemStyle: { areaColor: filteredOut ? '#172033' : value === null ? (completed === rows.length && completed ? '#7f1d1d' : '#1e293b') : latencyColor(value),
        borderColor: province === p ? '#f8fafc' : summary.failed || summary.partial ? '#facc15' : '#08101f', borderWidth: province === p || summary.failed || summary.partial ? 2 : 1 },
      carriers: Object.entries(carriers).filter(([key]) => !carrier || carrier === key).map(([key, label]) => {
        const list = rows.filter(n => n.carrier === key), v = median(list.flatMap(n => n.result?.median_ms != null ? [n.result.median_ms] : []));
        const s = connectionSummary(list);
        return `${label}：${v === null ? '无有效时延' : v.toFixed(1) + ' ms'} · ${s.success}/${s.attempts} 建连成功<br/>${escape(summaryState(s))}`;
      }),
    };
  }), ...['台湾省', '香港特别行政区', '澳门特别行政区'].filter(name => !nodes.some(n => fullName(n.province) === name)).map(name => ({
    name, short: '', value: null, completed: 0, total: 0, good: 0, carriers: [], filteredOut: false,
    itemStyle: { areaColor: '#475569', borderColor: '#a8b7cb', borderWidth: 1 },
    label: { show: false },
  }))], [nodes, province, carrier, status]);
  useEffect(() => {
    let active = true;
    loadMapData().then(value => { if (active) setMapData(value); }).catch(() => { if (active) setMapData(null); });
    return () => { active = false; };
  }, []);
  useEffect(() => {
    if (!el.current) return;
    const c = echarts.init(el.current, undefined, { renderer: 'canvas' }); chart.current = c;
    c.on('click', (event: unknown) => {
      const d = (event as { data?: { short?: string } }).data;
      if (d?.short) callback.current(d.short);
    });
    // Crossing the mobile breakpoint briefly hides desktop maps before React
    // removes them. ECharts 6 cannot invert a zero-sized geographic transform.
    const resize = new ResizeObserver(() => {
      if (el.current && el.current.clientWidth > 0 && el.current.clientHeight > 0 && !c.isDisposed()) c.resize();
    }); resize.observe(el.current);
    return () => { resize.disconnect(); c.dispose(); chart.current = undefined; };
  }, []);
  useEffect(() => {
    if (!mapData || !mapName) return;
    chart.current?.setOption({ animation: false, tooltip: { trigger: 'item', confine: true, backgroundColor: '#0f172a', borderColor: '#475569', textStyle: { color: '#f8fafc', fontSize: 12 },
      formatter: (event: unknown) => {
        const d = (event as { name: string; data?: typeof data[number] });
        if (d.data?.filteredOut) return `${escape(d.name)}<br/>该省没有符合当前筛选的结果；请调整筛选或选择其他省份。`;
        return d.data?.total ? `<b>${escape(d.name)}</b><br/>${d.data.value === null ? '无有效时延' : d.data.value.toFixed(1) + ' ms · 中位数'}<br/>已返回 ${d.data.completed}/${d.data.total} · 可达 ${d.data.good}/${d.data.total}<br/>${d.data.carriers.join('<br/>')}` : `${escape(d.name || '南海诸岛')}<br/>${d.name === '台湾省' ? '本次记录未检测 · 新测试使用指定 TCP 目标（端口 36901）' : '未检测 · 目录暂无测试目标'}`;
      } }, series: [{ type: 'map', map: mapName, roam: false,
        // layoutCenter/layoutSize retain the geographic aspect ratio. Setting
        // all four box edges independently stretches the map on wide panels.
        layoutCenter: ['50%', '50%'], layoutSize: '96%',
        label: { show: false }, itemStyle: { areaColor: '#172033', borderColor: '#08101f', borderWidth: 1 },
        emphasis: { label: { show: false }, itemStyle: { borderColor: '#e2e8f0', borderWidth: 2 } }, data }] }, { notMerge: true });
  }, [data, mapData, mapName]);
  return <div className="tcp-map" ref={el} role="img" aria-label={`${province ? province + '省级区域聚焦图' : '全国省级'} TCP 地图，当前显示${carriers[carrier] || '全部运营商'}。可通过省份表格或筛选器选择区域；台湾指定目标独立统计。`} />;
};
