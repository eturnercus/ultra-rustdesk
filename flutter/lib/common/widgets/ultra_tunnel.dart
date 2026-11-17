// Ultra RustDesk: P2P tunnel through NAT. The PC shows an invite code, the controller enters it
// and gets an answer code, the PC owner pastes the answer back, and both sides punch through
// their routers. No server of ours is involved (see src/ultra_tunnel.rs).
import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../../common.dart';
import '../../models/platform_model.dart';
import 'ultra_diag.dart';

String _compact(String s) => s.replaceAll(RegExp(r'[\s-]'), '').toUpperCase();

bool _isCode(String compact, String prefix) =>
    compact.length > 20 &&
    compact.startsWith(prefix) &&
    RegExp(r'^[A-Z2-7]+$').hasMatch(compact);

/// True for an invite code ("UT..."), which is entered like an ID.
bool isUltraTunnelInvite(String id) => _isCode(_compact(id), 'UT');

Widget _codeBox(BuildContext context, String code) {
  return Container(
    width: double.infinity,
    padding: const EdgeInsets.all(10),
    decoration: BoxDecoration(
      color: MyTheme.accent.withOpacity(0.08),
      border: Border.all(color: MyTheme.accent.withOpacity(0.5)),
      borderRadius: BorderRadius.circular(6),
    ),
    child: Row(
      children: [
        Expanded(
          child: SelectableText(code,
              style: const TextStyle(
                  fontFamily: 'monospace',
                  fontSize: 13,
                  fontWeight: FontWeight.bold)),
        ),
        IconButton(
          tooltip: translate('Copy'),
          icon: const Icon(Icons.copy, size: 18),
          onPressed: () {
            Clipboard.setData(ClipboardData(text: code));
            showToast(translate('Copied'));
          },
        ),
      ],
    ),
  );
}

Widget _title() => Row(children: [
      Icon(Icons.vpn_lock, color: MyTheme.accent),
      const SizedBox(width: 8),
      Text(translate('P2P tunnel')),
    ]);

/// Controller side: shows the answer code for an invite (already copied to the clipboard).
/// Returns true when the user chose to connect; the connection then waits up to three minutes
/// for the PC to accept the answer.
Future<bool> ultraTunnelPrepare(String invite) async {
  final res = await bind.mainUltraTunnelAnswer(code: invite);
  if (res.isEmpty) return true;
  final isError = res.startsWith('error:');
  final text = res.substring(res.indexOf(':') + 1);
  if (!isError) {
    // Ready to paste into a messenger at once.
    Clipboard.setData(ClipboardData(text: text));
    showToast(translate('ultra-tunnel-answer-copied'));
  }
  final ok = await gFFI.dialogManager.show<bool>((setState, close, context) {
    return CustomAlertDialog(
      title: _title(),
      content: SizedBox(
        width: 520,
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: isError
              ? [Text(text, style: const TextStyle(color: Colors.red))]
              : [
                  Text(translate('ultra-tunnel-answer-tip')),
                  const SizedBox(height: 10),
                  Text(translate('Answer code'),
                      style: const TextStyle(fontWeight: FontWeight.bold)),
                  const SizedBox(height: 4),
                  _codeBox(context, text),
                ],
        ),
      ),
      actions: [
        dialogButton('Connection log',
            isOutline: true,
            onPressed: () => showUltraDiag(gFFI.dialogManager)),
        dialogButton('Cancel', isOutline: true, onPressed: () => close(false)),
        if (!isError) dialogButton('Connect', onPressed: () => close(true)),
      ],
      onCancel: () => close(false),
    );
  });
  return ok == true;
}

/// PC side: makes an invite code and takes the controller's answer code.
void showUltraTunnelHost(OverlayDialogManager dialogManager) {
  bind.mainUltraTunnelInvite();
  dialogManager.show((setState, close, context) => CustomAlertDialog(
        title: _title(),
        content: const _TunnelHostView(),
        actions: [
          dialogButton('Connection log',
              isOutline: true, onPressed: () => showUltraDiag(dialogManager)),
          dialogButton('Close', onPressed: close),
        ],
        onCancel: close,
      ));
}

class _TunnelHostView extends StatefulWidget {
  const _TunnelHostView();

  @override
  State<_TunnelHostView> createState() => _TunnelHostViewState();
}

class _TunnelHostViewState extends State<_TunnelHostView> {
  String _state = 'preparing';
  Timer? _timer;
  final _answer = TextEditingController();
  String _copied = '';
  String _tried = '';

  @override
  void initState() {
    super.initState();
    _timer =
        Timer.periodic(const Duration(milliseconds: 700), (_) => _refresh());
  }

  Future<void> _refresh() async {
    final s = await bind.mainUltraTunnelState();
    if (!mounted) return;
    if (s != _state && s.isNotEmpty) setState(() => _state = s);
    if (s.startsWith('invite:')) {
      final code = s.substring('invite:'.length);
      if (code != _copied) {
        // Ready to paste into a messenger at once.
        _copied = code;
        Clipboard.setData(ClipboardData(text: code));
        showToast(translate('ultra-tunnel-invite-copied'));
      }
    }
    if (s.startsWith('invite:') || s.startsWith('badanswer:')) {
      await _answerFromClipboard();
    }
  }

  /// The answer usually arrives in a messenger and gets copied there: take it from the
  /// clipboard and accept it with no further click.
  Future<void> _answerFromClipboard() async {
    final data = await Clipboard.getData(Clipboard.kTextPlain);
    final text = (data?.text ?? '').trim();
    final compact = _compact(text);
    if (!mounted || compact == _tried || !_isCode(compact, 'UA')) return;
    _answer.text = text;
    _accept();
  }

  void _accept() {
    final a = _answer.text.trim();
    if (a.isEmpty) return;
    _tried = _compact(a);
    bind.mainUltraTunnelAccept(answer: a);
    setState(() => _state = 'waiting:');
  }

  @override
  void dispose() {
    _timer?.cancel();
    _answer.dispose();
    super.dispose();
  }

  String _after(String prefix) => _state.substring(prefix.length);

  Widget _spinner(String text) => Row(children: [
        const SizedBox(
            width: 16,
            height: 16,
            child: CircularProgressIndicator(strokeWidth: 2)),
        const SizedBox(width: 10),
        Expanded(child: Text(text)),
      ]);

  @override
  Widget build(BuildContext context) {
    final children = <Widget>[
      Text(translate('ultra-tunnel-host-tip')),
      const SizedBox(height: 12),
    ];
    if (_state == 'preparing') {
      children.add(_spinner(translate('ultra-tunnel-preparing')));
    } else if (_state.startsWith('invite:') ||
        _state.startsWith('badanswer:')) {
      final code = _state.substring(_state.indexOf(':') + 1);
      children.addAll([
        Text('1. ${translate('Invite code')}',
            style: const TextStyle(fontWeight: FontWeight.bold)),
        const SizedBox(height: 4),
        _codeBox(context, code),
        const SizedBox(height: 12),
        Text('2. ${translate('Answer code')}',
            style: const TextStyle(fontWeight: FontWeight.bold)),
        const SizedBox(height: 4),
        Row(children: [
          Expanded(
            child: TextField(
              controller: _answer,
              onSubmitted: (_) => _accept(),
              decoration: InputDecoration(
                hintText: 'UA...',
                helperText: translate('ultra-tunnel-auto-tip'),
                helperMaxLines: 2,
                errorText: _state.startsWith('badanswer:')
                    ? translate('ultra-tunnel-bad-answer')
                    : null,
                errorMaxLines: 2,
              ),
            ),
          ),
          const SizedBox(width: 8),
          ElevatedButton(
            onPressed: _accept,
            child: Text(translate('Accept')),
          ),
        ]),
      ]);
    } else if (_state.startsWith('waiting:')) {
      children.add(_spinner(translate('ultra-tunnel-waiting')));
    } else if (_state.startsWith('connected:')) {
      children.add(Row(children: [
        const Icon(Icons.check_circle, color: Colors.green),
        const SizedBox(width: 8),
        Expanded(
            child: Text('${translate('Connected')}: ${_after('connected:')}')),
      ]));
    } else if (_state == 'closed') {
      children.addAll([
        Text(translate('ultra-tunnel-closed')),
        const SizedBox(height: 8),
        _againButton(),
      ]);
    } else if (_state.startsWith('error:')) {
      children.addAll([
        Text(_after('error:'), style: const TextStyle(color: Colors.red)),
        const SizedBox(height: 8),
        _againButton(),
      ]);
    }
    return SizedBox(
      width: 540,
      child: Column(
        mainAxisSize: MainAxisSize.min,
        crossAxisAlignment: CrossAxisAlignment.start,
        children: children,
      ),
    );
  }

  Widget _againButton() => OutlinedButton(
        onPressed: () {
          _answer.clear();
          _tried = '';
          bind.mainUltraTunnelInvite();
          setState(() => _state = 'preparing');
        },
        child: Text(translate('ultra-tunnel-new-invite')),
      );
}
