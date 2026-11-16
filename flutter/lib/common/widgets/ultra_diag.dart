// Ultra RustDesk: live connection journal. Every step of a direct connection is shown as it
// happens (address, transport, time, why it failed), so it is clear where a connection stalls.
import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:get/get.dart';

import '../../common.dart';
import '../../models/platform_model.dart';

void showUltraDiag(OverlayDialogManager dialogManager) {
  dialogManager.show((setState, close, context) => CustomAlertDialog(
        title: Text(translate('Connection log')),
        content: const _UltraDiagView(),
        actions: [
          dialogButton('Clear', isOutline: true, onPressed: () {
            bind.mainUltraDiagClear();
          }),
          dialogButton('Copy to clipboard', isOutline: true, onPressed: () async {
            final text = await bind.mainUltraDiagLog();
            Clipboard.setData(ClipboardData(text: text));
            showToast(translate('Copied'));
          }),
          dialogButton('Close', onPressed: close),
        ],
        onCancel: close,
      ));
}

class _UltraDiagView extends StatefulWidget {
  const _UltraDiagView();

  @override
  State<_UltraDiagView> createState() => _UltraDiagViewState();
}

class _UltraDiagViewState extends State<_UltraDiagView> {
  String _text = '';
  Timer? _timer;
  final _scroll = ScrollController();

  @override
  void initState() {
    super.initState();
    _refresh();
    _timer = Timer.periodic(
        const Duration(milliseconds: 700), (_) => _refresh());
  }

  Future<void> _refresh() async {
    final text = await bind.mainUltraDiagLog();
    if (!mounted || text == _text) return;
    final atBottom = !_scroll.hasClients ||
        _scroll.position.pixels >= _scroll.position.maxScrollExtent - 24;
    setState(() => _text = text);
    if (atBottom) {
      WidgetsBinding.instance.addPostFrameCallback((_) {
        if (_scroll.hasClients) {
          _scroll.jumpTo(_scroll.position.maxScrollExtent);
        }
      });
    }
  }

  @override
  void dispose() {
    _timer?.cancel();
    _scroll.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final size = MediaQuery.of(context).size;
    return SizedBox(
      width: size.width < 720 ? size.width * 0.9 : 680,
      height: size.height * 0.6,
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(translate('ultra-diag-tip'),
                  style: const TextStyle(fontSize: 12))
              .marginOnly(bottom: 8),
          Expanded(
            child: Container(
              width: double.infinity,
              padding: const EdgeInsets.all(8),
              decoration: BoxDecoration(
                color: Colors.black87,
                borderRadius: BorderRadius.circular(6),
              ),
              child: SingleChildScrollView(
                controller: _scroll,
                child: SelectableText(
                  _text,
                  style: const TextStyle(
                      fontFamily: 'monospace',
                      fontSize: 11.5,
                      color: Color(0xFFB8F5C0),
                      height: 1.35),
                ),
              ),
            ),
          ),
        ],
      ),
    );
  }
}
