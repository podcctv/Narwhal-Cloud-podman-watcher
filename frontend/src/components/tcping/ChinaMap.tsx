import React, { useEffect, useMemo, useRef } from 'react';
import * as echarts from 'echarts/core';
import { MapChart } from 'echarts/charts';
import { TooltipComponent } from 'echarts/components';
import { CanvasRenderer } from 'echarts/renderers';
import china from '../../china-map.json';
import { carriers, latencyColor, median, Target } from './types';

echarts.use([MapChart, TooltipComponent, CanvasRenderer]);
const fullName = (name: string) => ({ 内蒙古: '内蒙古自治区', 广西: '广西壮族自治区', 西藏: '西藏自治区', 宁夏: '宁夏回族自治区', 新疆: '新疆维吾尔自治区', 北京: '北京市', 天津: '天津市', 上海: '上海市', 重庆: '重庆市' }[name] || name + '省');
echarts.registerMap('narwhal-china', china as Parameters<typeof echarts.registerMap>[1]);
const escape = (s: string) => s.replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]!));

export const ChinaMap: React.FC<{ nodes: Target[]; province: string; onSelect: (value: string) => void }> = ({ nodes, province, onSelect }) => {
  const el = useRef<HTMLDivElement>(null);
  const chart = useRef<echarts.ECharts>();
  const callback = useRef(onSelect); callback.current = onSelect;
  const data = useMemo(() => [...new Set(nodes.map(n => n.province))].map(p => {
    const rows = nodes.filter(n => n.province === p), measured = rows.filter(n => n.result);
    const good = rows.flatMap(n => n.result?.median_ms != null ? [n.result.median_ms] : []);
    const value = median(good);
    return { name: fullName(p), short: p, value, completed: measured.length, total: rows.length, good: good.length,
      itemStyle: { areaColor: value === null ? (measured.length === rows.length && measured.length ? '#7f1d1d' : '#1e293b') : latencyColor(value),
        borderColor: province === p ? '#f8fafc' : '#08101f', borderWidth: province === p ? 2 : 1 },
      carriers: Object.entries(carriers).map(([key, label]) => {
        const list = rows.filter(n => n.carrier === key), v = median(list.flatMap(n => n.result?.median_ms != null ? [n.result.median_ms] : []));
        return `${label}：${v === null ? '未获得有效连接' : v.toFixed(1) + ' ms'} · ${list.filter(n => n.result?.success).length}/${list.length} 可达`;
      }),
    };
  }), [nodes, province]);
  useEffect(() => {
    if (!el.current) return;
    const c = echarts.init(el.current, undefined, { renderer: 'canvas' }); chart.current = c;
    c.on('click', (event: unknown) => {
      const d = (event as { data?: { short?: string } }).data;
      if (d?.short) callback.current(d.short);
    });
    const resize = new ResizeObserver(() => c.resize()); resize.observe(el.current);
    return () => { resize.disconnect(); c.dispose(); chart.current = undefined; };
  }, []);
  useEffect(() => {
    chart.current?.setOption({ animation: false, tooltip: { trigger: 'item', confine: true, backgroundColor: '#0f172a', borderColor: '#475569', textStyle: { color: '#f8fafc', fontSize: 12 },
      formatter: (event: unknown) => {
        const d = (event as { name: string; data?: typeof data[number] });
        return d.data ? `<b>${escape(d.name)}</b><br/>${d.data.value === null ? '无有效时延' : d.data.value.toFixed(1) + ' ms · 中位数'}<br/>已返回 ${d.data.completed}/${d.data.total} · 可达 ${d.data.good}/${d.data.total}<br/>${d.data.carriers.join('<br/>')}` : `${escape(d.name || '南海诸岛')}<br/>目录无测试目标`;
      } }, series: [{ type: 'map', map: 'narwhal-china', roam: false, left: '2%', right: '2%', top: '5%', bottom: '5%',
        label: { show: false }, itemStyle: { areaColor: '#172033', borderColor: '#08101f', borderWidth: 1 },
        emphasis: { label: { show: false }, itemStyle: { borderColor: '#e2e8f0', borderWidth: 2 } }, data }] });
  }, [data]);
  return <div className="tcp-map" ref={el} role="img" aria-label="中国各省 TCP 连接时延地图。可使用右侧省份筛选查看相同数据。" />;
};
