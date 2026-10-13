/* Compute-only membership. Existing HCI/SCVM wizard behavior is kept separate. */
var ComputeNodes = (function () {
  let mode = 'add';
  let nodes = [];
  let checked = null;
  let busy = false;
  let pending = false;
  let loaded;
  let returnFocus;
  let returnToWizard = false;
  let coordinator;
  let callerReset = false;
  const root = '#div-modal-compute-node';

  function api(action, payload) {
    const process = cockpit.spawn(['python3', pluginpath + '/python/cluster/compute_node.py', action], {superuser: 'require'});
    if (action !== 'list') process.input(JSON.stringify(payload || {}));
    process.input(null);
    return Promise.resolve(process).then(output => {
      const result = JSON.parse(output);
      if (result.code !== 200 && result.code !== 207) throw new Error(String(result.val));
      return result;
    });
  }
  function feedback(message, failed, success = false) {
    $('#compute-node-feedback').text(message);
    const tone = failed ? 'danger' : success ? 'success' : 'info';
    $('#compute-node-status').removeClass('pf-m-info pf-m-success pf-m-danger').addClass('pf-m-' + tone);
    $('#compute-node-status-title').text(failed ? '확인이 필요합니다' : success ? '확인 완료' : '진행 안내');
    $('#compute-node-status-icon').attr('class', 'fas ' + (failed ? 'fa-exclamation-circle' : success ? 'fa-check-circle' : 'fa-info-circle'));
  }
  function canCheck() {
    return !busy && !pending && !callerReset && (mode !== 'remove' ||
      !!$('#compute-node-target').val() && $('#compute-node-mold-released').prop('checked'));
  }
  function setBusy(value, phase = 'check') {
    busy = value;
    $(root).attr('aria-busy', String(value));
    const checking = value && phase === 'check';
    const executing = value && phase === 'execute';
    // hidden is supported on HTML progress containers, not on SVG elements.
    $('#compute-node-check-progress').prop('hidden', !checking);
    $('#compute-node-execute-progress').prop('hidden', !executing);
    $('#compute-node-check').attr('aria-busy', String(checking)).toggleClass('pf-m-in-progress', checking);
    $('#compute-node-execute').attr('aria-busy', String(executing)).toggleClass('pf-m-in-progress', executing);
    $('#compute-node-check-label').text(checking ? '확인 중' : '사전 확인');
    $('#compute-node-execute-label').text(executing ? '설정 제거 중' : mode === 'add' ? '추가 실행' : '설정 제거 실행');
    $(root + ' input, ' + root + ' select, ' + root + ' button').prop('disabled', value);
    if (!value) {
      $('#compute-node-check').prop('disabled', !canCheck());
      $('#compute-node-execute').prop('disabled', pending || !checked);
      if (callerReset) $('#compute-node-pending button').prop('disabled', true);
    }
    $('#compute-node-check').toggleClass('pf-m-primary', !checked).toggleClass('pf-m-secondary', !!checked);
    $('#compute-node-execute').toggleClass('pf-m-primary', !!checked && mode === 'add').toggleClass('pf-m-danger', !!checked && mode === 'remove').toggleClass('pf-m-secondary', !checked);
    if (value) $(root + ' [role=dialog]').trigger('focus');
    else if ($(document.activeElement).is(root + ' [role=dialog]')) $(pending ? root + ' .compute-node-close' : checked ? '#compute-node-execute' : '#compute-node-check').first().trigger('focus');
  }
  function invalidate() {
    checked = null;
    $('#compute-node-review').prop('hidden', true).empty();
    $('#compute-node-execute').prop('disabled', true).removeClass('pf-m-primary pf-m-danger').addClass('pf-m-secondary');
    $('#compute-node-check').prop('disabled', !canCheck()).removeClass('pf-m-secondary').addClass('pf-m-primary');
  }
  function payload() {
    if (mode === 'add') {
      const value = {hostname: $('#compute-node-hostname').val().trim(), ablecube: $('#compute-node-ip').val().trim(), ablecubePn: $('#compute-node-hpn').val().trim()};
      if (!value.hostname || !value.ablecube || !value.ablecubePn) throw new Error('호스트명, 호스트 IP, HPN IP를 모두 입력하십시오.');
      return value;
    }
    const hostname = $('#compute-node-target').val();
    if (!hostname) throw new Error('제거할 컴퓨팅 노드를 선택하십시오.');
    const value = {hostname, offline: false, moldReleased: $('#compute-node-mold-released').prop('checked')};
    if (!value.moldReleased) throw new Error('Mold에서 VM과 호스트 정리를 완료했는지 확인하십시오.');
    return value;
  }
  function targetInfo() {
    const node = nodes.find(item => item.hostname === $('#compute-node-target').val());
    $('#compute-node-selected-hostname').text(node ? node.hostname : '-');
    $('#compute-node-selected-ip').text(node ? node.ablecube : '-');
    $('#compute-node-selected-hpn').text(node ? node.ablecubePn : '-');
    $('#compute-node-target-info').text(node ? '사전 확인에서 SSH 접속과 제거 가능 여부를 검사합니다.' : '등록된 컴퓨팅 노드가 없습니다.');
  }
  async function refresh() {
    const result = await api('list');
    coordinator = result.val.coordinator;
    nodes = result.val.nodes;
    const selected = $('#compute-node-target').val();
    $('#compute-node-target').empty();
    nodes.forEach(node => $('<option>').val(node.hostname).text(node.hostname).appendTo('#compute-node-target'));
    if (nodes.some(n => n.hostname === selected)) $('#compute-node-target').val(selected);
    targetInfo();
    const operations = result.val.operations;
    pending = operations.length > 0;
    $('#compute-node-pending').empty();
    operations.forEach(operation => {
      const row = $('<div class="compute-node-operation">').append($('<p>').text(operation.node.hostname + ': ' + (operation.action === 'add' ? '추가' : '제거') + ' 미완료'));
      (operation.errors || []).forEach(error => row.append($('<p>').text(error.step + ': ' + error.message)));
      $('<button type="button" class="pf-v6-c-button pf-m-secondary">').text('처음부터 다시 실행').on('click', () => perform('retry', {id: operation.id})).appendTo(row);
      row.appendTo('#compute-node-pending');
    });
    (result.val.cleanupPending || []).forEach(operation => {
      const row = $('<div class="compute-node-operation">').append($('<p>').text(operation.node.hostname + ': 등록 제거 완료 / 대상 호스트 내부 정리 미완료'));
      $('<button type="button" class="pf-v6-c-button pf-m-secondary">').text('대상 호스트 내부 정리').on('click', () => perform('cleanup-offline', {id: operation.id})).appendTo(row);
      row.appendTo('#compute-node-pending');
    });
    if (!result.val.supported) {
      pending = true;
      feedback('구성된 ABLESTACK HCI 클러스터 호스트에서 컴퓨팅 노드를 관리하십시오.', true);
    }
  }
  async function perform(action, value) {
    if (busy) return;
    setBusy(true, 'execute');
    feedback('설정 작업 중입니다. 완료될 때까지 기다려 주십시오.');
    try {
      const result = await api(action, value);
      invalidate();
      const operation = result.val;
      callerReset = operation.callerReset === true;
      coordinator = operation.coordinator || coordinator;
      if (callerReset) {
        pending = true;
        $('#compute-node-pending').empty();
        $('#compute-node-target').empty();
        targetInfo();
        $('#compute-node-target-info').text('현재 접속한 호스트의 클러스터 설정이 초기화되었습니다.');
      } else {
        await refresh();
      }
      const messages = operation.messages || [];
      const errors = (operation.errors || []).map(error => error.step + ': ' + error.message);
      if (callerReset && coordinator) messages.push('현재 호스트의 클러스터 SSH 키와 설정이 초기화되었습니다. 추가 관리·처음부터 다시 실행는 기준 호스트 ' + coordinator.hostname + ' (' + coordinator.ip + ')의 Cockpit에서 진행하십시오.');
      feedback([result.code === 200 ? '컴퓨팅 노드 ' + (operation.action === 'add' ? '준비' : '설정 제거') + ' 완료' : '작업이 완료되지 않았습니다. 처음부터 다시 실행하십시오.', ...messages, ...errors].join('\n'), result.code !== 200, result.code === 200);
    } catch (error) {
      let message = error.message;
      try { await refresh(); } catch (_) {
        pending = true;
        if (coordinator) message += '\n기준 호스트 ' + coordinator.hostname + ' (' + coordinator.ip + ')의 Cockpit에서 작업 기록을 확인하고 재시도하십시오.';
      }
      feedback(message, true);
    } finally { setBusy(false); }
  }
  async function open(nextMode) {
    if (busy) return;
    if (nextMode === 'add') {
      // The cluster wizard loads asynchronously with main.html.
      const deadline = Date.now() + 10000;
      while (!window.ClusterConfigCompute && Date.now() < deadline) await new Promise(resolve => setTimeout(resolve, 50));
      if (window.ClusterConfigCompute) return ClusterConfigCompute.open();
      createLoggerInfo('클러스터 구성 준비 화면을 불러오지 못했습니다.');
      return;
    }
    returnFocus = document.activeElement;
    returnToWizard = $('#div-modal-wizard-cluster-config-prepare').is(':visible');
    mode = nextMode;
    callerReset = false;
    if (!loaded) loaded = new Promise((resolve, reject) => $(root).load('./src/features/compute-node.html', (_, status) => status === 'error' ? reject(new Error('화면을 불러오지 못했습니다.')) : resolve()));
    try { await loaded; } catch (error) { loaded = null; console.error(error); return; }
    $(root).show();
    $('#div-modal-wizard-cluster-config-prepare').hide();
    invalidate();
    $('#compute-node-title').text(mode === 'add' ? '컴퓨팅 노드 추가' : '컴퓨팅 노드 설정 제거');
    $('#compute-node-description').text(mode === 'add' ? 'SCVM 없이 VM을 실행할 호스트를 기존 클러스터에 추가합니다.' : 'VM 정리가 끝난 컴퓨팅 노드의 클러스터 구성과 완료 상태를 초기화합니다.');
    $('#compute-node-add-guide').prop('hidden', mode !== 'add');
    $('#compute-node-add-fields').prop('hidden', mode !== 'add');
    $('#compute-node-remove-fields').prop('hidden', mode !== 'remove');
    $('#compute-node-execute-label').text(mode === 'add' ? '추가 실행' : '설정 제거 실행');
    $('#compute-node-form input[type=checkbox]').prop('checked', false);
    feedback('목록을 확인하고 있습니다.');
    setBusy(true);
    try { await refresh(); if (!pending) feedback('Mold에서 VM과 호스트 정리 완료를 체크한 뒤 사전 확인을 실행하십시오.'); }
    catch (error) { pending = true; feedback(error.message, true); }
    finally {
      setBusy(false);
      $(mode === 'add' ? '#compute-node-hostname' : '#compute-node-target').trigger('focus');
    }
  }
  $(document).on('input change', '#compute-node-form input, #compute-node-form select', function () {
    if (this.id === 'compute-node-target') $('#compute-node-mold-released').prop('checked', false);
    invalidate();
    feedback('입력이 변경되었습니다. 사전 확인을 다시 실행하십시오.');
    targetInfo();
  });
  $(document).on('submit', '#compute-node-form', event => event.preventDefault());
  function close() {
    if (busy) return;
    $(root).hide();
    if (returnToWizard) $('#div-modal-wizard-cluster-config-prepare').show();
    if (returnFocus && returnFocus.isConnected) returnFocus.focus();
  }
  $(document).on('click', '.compute-node-close', close);
  $(document).on('keydown', root, function (event) {
    if (event.key === 'Escape') { event.preventDefault(); event.stopPropagation(); close(); }
    if (event.key !== 'Tab') return;
    const items = $(root).find('button:enabled, input:enabled, select:enabled').filter(':visible').toArray();
    if (!items.length) { event.preventDefault(); return; }
    const first = items[0], last = items[items.length - 1];
    if (event.shiftKey && (document.activeElement === first || !items.includes(document.activeElement))) { event.preventDefault(); last.focus(); }
    else if (!event.shiftKey && (document.activeElement === last || !items.includes(document.activeElement))) { event.preventDefault(); first.focus(); }
  });
  $(document).on('click', '#compute-node-check', async function () {
    if (!canCheck()) return;
    let value;
    try { value = payload(); } catch (error) { feedback(error.message, true); return; }
    setBusy(true);
    feedback('SSH 접속과 호스트 상태를 확인하고 있습니다.');
    try {
      const result = await api('preflight-' + mode, value);
      checked = value;
      const node = result.val.node;
      const review = $('#compute-node-review').prop('hidden', false).empty().append($('<h2>').text('실행 대상 확인'));
      if (mode === 'add') {
        const details = $('<dl>').appendTo(review);
        [['호스트명', node.hostname], ['호스트 IP', node.ablecube], ['HPN IP', node.ablecubePn]].forEach(([label, value]) => $('<div>').append($('<dt>').text(label), $('<dd>').text(value)).appendTo(details));
      }
      $('<p>').text(mode === 'add' ? '기존 설정과 SSH 키, Ceph 인증 정보를 적용합니다. SCVM은 생성하지 않습니다.' : value.offline ? '대상 노드의 등록 정보만 제거합니다. SSH 키·구성 파일·nwfilter 초기화는 접속 복구 후 별도로 실행합니다.' : '대상 노드의 클러스터 SSH 키·구성 파일·완료 상태·nwfilter 설정을 초기화하고 남은 노드의 등록 정보를 정리합니다.').appendTo(review);
      feedback(result.val.checks.join('\n') + '\n확인한 대상으로 실행할 수 있습니다.', false, true);
      if (mode === 'remove') $('#compute-node-target-info').text('SSH 접속과 제거 가능 여부를 확인했습니다.');
    } catch (error) { invalidate(); feedback(error.message, true); }
    finally { setBusy(false); }
  });
  $(document).on('click', '#compute-node-execute', () => { if (checked && !busy && !pending) perform(mode, checked); });
  $(document).on('click', '[data-compute-action]', function () { open($(this).attr('data-compute-action')); });
  return {open, api};
})();
